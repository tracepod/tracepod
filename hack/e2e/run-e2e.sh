#!/usr/bin/env bash
# run-e2e.sh — full end-to-end test: sensor profiles nginx, harden builds a
# FROM-scratch image, validation confirms 'nginx -t' passes.
#
# Runs in two contexts:
#   - Inside the k8s-dev Lima VM  (arm64, Docker + kind installed)
#   - Directly on an ubuntu-latest CI runner (amd64, sensor binary pre-built)
#
# Usage:
#   bash hack/e2e/run-e2e.sh [--keep-cluster]
#
#   --keep-cluster   Skip kind cluster deletion on exit (useful for debugging).
#
# Environment variables:
#   SENSOR_IMAGE   Docker image for the sensor (default: tracepod-sensor:e2e)
#   CLUSTER_NAME   kind cluster name (default: tracepod-e2e)
#   PROFILE_DIR    host-side profile output directory (default: /tmp/tracepod-e2e-profiles)
#   REGISTRY_PORT  local OCI registry port (default: 5001)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SENSOR_IMAGE="${SENSOR_IMAGE:-tracepod-sensor:e2e}"
CLUSTER_NAME="${CLUSTER_NAME:-tracepod-e2e}"
PROFILE_DIR="${PROFILE_DIR:-/tmp/tracepod-e2e-profiles}"
REGISTRY_PORT="${REGISTRY_PORT:-5001}"
REGISTRY_NAME="e2e-registry"
HARDENED_IMAGE="localhost:${REGISTRY_PORT}/nginx-hardened:e2e"
KEEP_CLUSTER=false
ARCH=$(uname -m)

for arg in "$@"; do
  case "$arg" in
    --keep-cluster) KEEP_CLUSTER=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# ── Colours ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[e2e]${NC} $*"; }
warn()  { echo -e "${YELLOW}[e2e]${NC} $*"; }
fail()  { echo -e "${RED}[e2e FAIL]${NC} $*" >&2; }

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    fail "e2e failed — collecting debug info"
    kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=80 2>/dev/null || true
    kubectl describe daemonset tracepod-sensor 2>/dev/null || true
    kubectl get pods -A 2>/dev/null || true
    info "Profile dir contents:"
    find "${PROFILE_DIR}" 2>/dev/null || true
  fi

  if [ "$KEEP_CLUSTER" = true ]; then
    warn "--keep-cluster set; skipping teardown (cluster: ${CLUSTER_NAME})"
    return
  fi

  info "Cleaning up..."
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  docker rm -f "${REGISTRY_NAME}" 2>/dev/null || true
  rm -rf "${PROFILE_DIR}" /tmp/hardened-nginx-oci /tmp/harden \
    /tmp/tracepod-e2e-kubeconfig.yaml 2>/dev/null || true
}
trap cleanup EXIT

# ── Phase 0: Prerequisites ──────────────────────────────────────────────────────
info "Phase 0: checking prerequisites"
for cmd in docker kind kubectl helm go; do
  command -v "$cmd" >/dev/null 2>&1 || { fail "required tool not found: $cmd"; exit 1; }
done
info "All prerequisites present (arch: ${ARCH})"

# ── Phase 1: Sensor Docker image ───────────────────────────────────────────────
info "Phase 1: building sensor image"
cd "${REPO_ROOT}"

if docker image inspect "${SENSOR_IMAGE}" >/dev/null 2>&1; then
  info "Sensor image ${SENSOR_IMAGE} already exists — skipping build"
elif [ "${ARCH}" = "aarch64" ]; then
  # Lima VM (arm64): arm64 BPF objects are committed to git, so Dockerfile.sensor
  # skips 'make generate' and builds without clang/bpftool on the host.
  info "Building sensor image for arm64 (Lima VM)"
  docker build --platform linux/arm64 -f Dockerfile.sensor -t "${SENSOR_IMAGE}" .
else
  # CI (amd64): sensor binary is expected to be pre-built on the runner by the
  # GitHub Actions workflow (which has /sys/kernel/btf for 'make generate').
  if [ ! -f "${REPO_ROOT}/sensor" ]; then
    fail "sensor binary not found at ${REPO_ROOT}/sensor — on amd64 the workflow must"
    fail "run 'make generate && CGO_ENABLED=0 go build -o sensor ./cmd/sensor' first"
    exit 1
  fi
  info "Building sensor image for amd64 (CI — from pre-built binary)"
  docker build -f Dockerfile.sensor.dev -t "${SENSOR_IMAGE}" .
fi

# ── Phase 2: kind cluster ───────────────────────────────────────────────────────
info "Phase 2: creating kind cluster '${CLUSTER_NAME}'"
# Start from a clean profile dir. The sensor writes profiles as root via the
# node hostPath, and this dir persists across runs, so stale profiles from an
# earlier run (possibly an older schema version) would otherwise be picked up by
# the `find | head -1` below. Remove with sudo since the files are root-owned.
sudo rm -rf "${PROFILE_DIR}" 2>/dev/null || rm -rf "${PROFILE_DIR}" 2>/dev/null || true
mkdir -p "${PROFILE_DIR}"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  warn "Cluster '${CLUSTER_NAME}' already exists — reusing"
else
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${SCRIPT_DIR}/kind-config.yaml"
fi

kind get kubeconfig --name "${CLUSTER_NAME}" > /tmp/tracepod-e2e-kubeconfig.yaml
export KUBECONFIG=/tmp/tracepod-e2e-kubeconfig.yaml

kind load docker-image "${SENSOR_IMAGE}" --name "${CLUSTER_NAME}"

# ── Phase 3: Helm install ───────────────────────────────────────────────────────
info "Phase 3: deploying tracepod sensor via Helm"
PLATFORM=$([ "${ARCH}" = "aarch64" ] && echo linux/arm64 || echo linux/amd64)

helm upgrade --install tracepod "${REPO_ROOT}/helm/tracepod" \
  --set sensor.image.repository="${SENSOR_IMAGE%%:*}" \
  --set sensor.image.tag="${SENSOR_IMAGE##*:}" \
  --set sensor.image.pullPolicy=Never \
  --set sensor.profileHostPath=/var/lib/tracepod/profiles

info "Waiting for sensor DaemonSet to be ready (up to 120s)..."
kubectl rollout status daemonset/tracepod-sensor --timeout=120s

# ── Phase 4: workload ──────────────────────────────────────────────────────────
info "Phase 4: deploying nginx workload"
kubectl create deployment nginx-e2e --image=nginx:alpine 2>/dev/null || \
  warn "nginx-e2e deployment already exists"

info "Waiting for nginx pod to be ready (up to 60s)..."
kubectl rollout status deployment/nginx-e2e --timeout=60s

info "Exercising nginx to trigger file-open events..."
kubectl exec deployment/nginx-e2e -- wget -qO- localhost/ >/dev/null || true
kubectl exec deployment/nginx-e2e -- nginx -s reload 2>/dev/null || true
kubectl exec deployment/nginx-e2e -- wget -qO- localhost/nginx-health >/dev/null 2>&1 || true

info "Scaling nginx to 0 (triggers NRI StopContainer → sensor profile flush)..."
kubectl scale deployment nginx-e2e --replicas=0

# ── Phase 5: wait for manifest ─────────────────────────────────────────────────
info "Phase 5: waiting for sensor manifest (up to 60s)..."
MANIFEST=""
for i in $(seq 1 30); do
  MANIFEST=$(find "${PROFILE_DIR}" -name "files.json" 2>/dev/null | head -1)
  if [ -n "$MANIFEST" ]; then
    info "Manifest found: ${MANIFEST}"
    break
  fi
  echo -n "."
  sleep 2
done
echo

if [ -z "$MANIFEST" ]; then
  fail "Manifest not found in ${PROFILE_DIR} after 60s"
  exit 1
fi

MANIFEST_SIZE=$(wc -c < "$MANIFEST")
info "Manifest size: ${MANIFEST_SIZE} bytes"
if [ "$MANIFEST_SIZE" -lt 100 ]; then
  fail "Manifest looks empty (< 100 bytes) — sensor may not have recorded any events"
  exit 1
fi

# ── Phase 5b: schema v3 assertions ─────────────────────────────────────────────
# The recorded run must carry the current integer schema_version, the v2
# coverage markers (R2/R3), and the v3 event_loss block. nginx is started AFTER
# the sensor here, so the process-start marker may be true or false depending on
# the startup race — we assert the field is present and boolean, not a specific
# value. The dedicated missed-start (always-false) and restart (start-count)
# scenarios, plus the induced-loss (event_loss.total > 0) scenario, are exercised
# by hack/record-profile-fixtures.sh and the manifest unit tests.
#
# This nginx run uses the default ring buffer and a light workload, so event_loss
# must be a TRUE ZERO: total == 0, every audited stage instrumented (present in
# by_stage), and nothing listed not_instrumented. A nonzero total here would be a
# real regression in drain throughput, not a flaky test.
if command -v jq >/dev/null 2>&1; then
  info "Phase 5b: asserting schema v5 shape on ${MANIFEST}"
  VER=$(jq -r '.schema_version' "$MANIFEST")
  if [ "$VER" != "5" ]; then
    fail "schema_version=${VER}, want integer 5"; exit 1
  fi

  # v5: adoption provenance. This run stops the container via NRI StopContainer,
  # so the sensor must report the start-anchored mode — anything else means the
  # container was adopted after it was already running, and the profile would be
  # truncated. Asserting the exact value (not just "present") is the point: it is
  # what makes a truncated window detectable at all.
  AM=$(jq -r '.coverage.adoption_mode // "missing"' "$MANIFEST")
  if [ "$AM" != "nri-start" ]; then
    fail "coverage.adoption_mode=${AM}, want nri-start for an NRI-started container"; exit 1
  fi
  info "coverage.adoption_mode=${AM}"

  # v5: terminality. The workload was scaled to 0, so the window closed because
  # the container stopped — this must be a terminal profile. A false here would
  # mean the file set is incomplete and must not be treated as evidence.
  TERM=$(jq -r '.profile_terminal // "missing"' "$MANIFEST")
  if [ "$TERM" != "true" ]; then
    fail "profile_terminal=${TERM}, want true after a clean container stop"; exit 1
  fi
  info "profile_terminal=${TERM}"
  PSO=$(jq -r '.coverage.process_start_observed' "$MANIFEST")
  case "$PSO" in
    true|false) info "coverage.process_start_observed=${PSO}" ;;
    *) fail "coverage.process_start_observed must be boolean, got '${PSO}'"; exit 1 ;;
  esac
  STARTS=$(jq -r '.container_starts | length' "$MANIFEST")
  if [ "${STARTS:-0}" -lt 1 ]; then
    fail "container_starts must have >=1 entry, got ${STARTS}"; exit 1
  fi
  info "container_starts entries: ${STARTS}"

  # event_loss (v3): present, true zero, fully instrumented.
  LOSS_TOTAL=$(jq -r '.event_loss.total' "$MANIFEST")
  if [ "${LOSS_TOTAL}" != "0" ]; then
    fail "event_loss.total=${LOSS_TOTAL}, want 0 (default buffer, light workload)"; exit 1
  fi
  NI=$(jq -r '.event_loss.not_instrumented | length' "$MANIFEST")
  if [ "${NI}" != "0" ]; then
    fail "event_loss.not_instrumented has ${NI} entries — live sensor must instrument every stage"; exit 1
  fi
  SUM=$(jq -r '[.event_loss.by_stage[]] | add // 0' "$MANIFEST")
  if [ "${SUM}" != "${LOSS_TOTAL}" ]; then
    fail "event_loss sum invariant broken: total=${LOSS_TOTAL} sum(by_stage)=${SUM}"; exit 1
  fi
  # tolerated (v3 + OSS-4b): path_read_failed must be present (instrumented) and is
  # EXCLUDED from total. It carries an intrinsic idle floor (0-2), so we assert it
  # is a non-negative integer and surface the value — never gate it at zero.
  PR=$(jq -r '.event_loss.tolerated.path_read_failed // "missing"' "$MANIFEST")
  if ! printf '%s' "${PR}" | grep -Eq '^[0-9]+$'; then
    fail "event_loss.tolerated.path_read_failed=${PR} — must be an instrumented integer"; exit 1
  fi
  STAGES=$(jq -r '.event_loss.by_stage | keys | length' "$MANIFEST")
  info "event_loss.total=${LOSS_TOTAL} across ${STAGES} hard stage(s); tolerated.path_read_failed=${PR}"
else
  warn "jq not found — skipping schema v5 shape assertions"
fi

# ── Phase 6: harden build ──────────────────────────────────────────────────────
info "Phase 6: building hardened nginx image"

info "Building harden binary..."
CGO_ENABLED=0 go build -o /tmp/harden "${REPO_ROOT}/cmd/harden"

info "Starting local OCI registry on port ${REGISTRY_PORT}..."
docker rm -f "${REGISTRY_NAME}" 2>/dev/null || true
docker run -d \
  --name "${REGISTRY_NAME}" \
  -p "${REGISTRY_PORT}:5000" \
  -e REGISTRY_STORAGE_DELETE_ENABLED=true \
  registry:2

# Give registry a moment to accept connections.
sleep 2

rm -rf /tmp/hardened-nginx-oci
/tmp/harden build \
  --manifest "${MANIFEST}" \
  --source nginx:alpine \
  --output /tmp/hardened-nginx-oci \
  --push "${HARDENED_IMAGE}" \
  --mkdir /var/cache/nginx \
  --mkdir /var/log/nginx \
  --touch /run/nginx.pid \
  --platform "${PLATFORM}" \
  --insecure

# ── Phase 6b: removal manifest assertion (OSS-3) ────────────────────────────────
info "Phase 6b: validating removal manifest"
REMOVAL_MANIFEST=/tmp/hardened-nginx-oci/removal-manifest.json
if [ ! -f "$REMOVAL_MANIFEST" ]; then
  fail "removal manifest not emitted at $REMOVAL_MANIFEST (is syft installed?)"; exit 1
fi
if command -v jq >/dev/null 2>&1; then
  SCHEMA=$(jq -r '.schema' "$REMOVAL_MANIFEST")
  SCHEMA_VER=$(jq -r '.schema_version' "$REMOVAL_MANIFEST")
  REMOVED_N=$(jq -r '.removed | length' "$REMOVAL_MANIFEST")
  info "removal-manifest schema=${SCHEMA} version=${SCHEMA_VER} removed_packages=${REMOVED_N}"
  [ "$SCHEMA" = "tracepod.dev/removal-manifest" ] || { fail "unexpected schema: $SCHEMA"; exit 1; }
  [ "$SCHEMA_VER" = "1.0" ] || { fail "unexpected schema_version: $SCHEMA_VER"; exit 1; }

  # Walk both images' filesystems via docker export and normalise to absolute
  # paths (tar entries are slash-less; directories carry a trailing slash).
  list_image_paths() {  # $1 = image ref → stdout: sorted, unique, absolute paths
    local cid
    cid=$(docker create "$1")
    docker export "$cid" | tar -tf - | sed -e 's#^\./##' -e 's#^#/#' -e 's#/\{2,\}#/#g' -e 's#/$##'
    docker rm "$cid" >/dev/null
  }
  list_image_paths nginx:alpine        | sort -u > /tmp/src-paths.txt
  list_image_paths "${HARDENED_IMAGE}" | sort -u > /tmp/hardened-paths.txt

  # R2 / integration check: every listed package must have ZERO files in the
  # hardened image and AT LEAST ONE in the source image.
  RM_FAILED=0
  while IFS= read -r pkg; do
    purl=$(echo "$pkg" | jq -r '.purl')
    in_source=0
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      if grep -Fxq "$p" /tmp/hardened-paths.txt; then
        warn "removed pkg ${purl}: path STILL PRESENT in hardened image: $p"
        RM_FAILED=1
      fi
      if grep -Fxq "$p" /tmp/src-paths.txt; then in_source=1; fi
    done < <(echo "$pkg" | jq -r '.paths[]?')
    if [ "$in_source" -eq 0 ]; then
      warn "removed pkg ${purl}: no listed path found in source image"
      RM_FAILED=1
    fi
  done < <(jq -c '.removed[]' "$REMOVAL_MANIFEST")
  [ "$RM_FAILED" -eq 0 ] || { fail "removal manifest assertion failed"; exit 1; }
  info "removal manifest OK: ${REMOVED_N} package(s), zero retained files each, all present in source"
else
  warn "jq not found — skipping removal manifest assertion"
fi

# ── Phase 7: validate ──────────────────────────────────────────────────────────
info "Phase 7: validating hardened nginx image"
docker pull --quiet "${HARDENED_IMAGE}"

docker run --rm \
  --tmpfs /var/log/nginx \
  --tmpfs /var/run \
  "${HARDENED_IMAGE}" \
  nginx -t

SOURCE_SIZE=$(docker image inspect nginx:alpine --format='{{.Size}}' 2>/dev/null || echo 0)
HARDENED_SIZE=$(docker image inspect "${HARDENED_IMAGE}" --format='{{.Size}}' 2>/dev/null || echo 0)

if [ "$SOURCE_SIZE" -gt 0 ] && [ "$HARDENED_SIZE" -gt 0 ]; then
  REDUCTION=$(( (SOURCE_SIZE - HARDENED_SIZE) * 100 / SOURCE_SIZE ))
  info "Size reduction: ${REDUCTION}% (${SOURCE_SIZE} → ${HARDENED_SIZE} bytes)"
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}  PASS: tracepod e2e test complete    ${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}"
