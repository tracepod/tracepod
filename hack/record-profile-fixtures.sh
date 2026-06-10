#!/usr/bin/env bash
# record-profile-fixtures.sh — record sensor profile documents verbatim into
# testdata/profile-fixtures/v<N>/ for cross-repo CI replay.
#
# These fixtures are RECORDED ARTIFACTS. Do not hand-edit them. To change them,
# re-run this script (locally inside the k8s-dev Lima VM, or via the
# `record-fixtures` workflow_dispatch which opens a PR). See
# testdata/profile-fixtures/README.md.
#
# What it does:
#   1. brings up a kind cluster + the tracepod sensor (DaemonSet) — same infra
#      as hack/e2e/run-e2e.sh;
#   2. deploys three representative workloads, each pinned BY DIGEST for
#      determinism:
#        - static    a fast-saturating static Go binary (hashicorp/http-echo)
#        - interp    an interpreted app (python) that opens many library files
#        - restart   a workload that exits and is restarted during the window
#   3. exercises and then stops them so the sensor flushes one profile per
#      container lifecycle;
#   4. copies each files.json verbatim into testdata/profile-fixtures/v<N>/,
#      named by workload.
#
# Usage:
#   bash hack/record-profile-fixtures.sh [--keep-cluster]
#
# Environment overrides: see the e2e script; plus
#   SCHEMA_VERSION   fixtures subdirectory version (default: read from manifest)
#   FIXTURE_DIR      output dir (default: testdata/profile-fixtures/v<N>)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SENSOR_IMAGE="${SENSOR_IMAGE:-tracepod-sensor:fixtures}"
CLUSTER_NAME="${CLUSTER_NAME:-tracepod-fixtures}"
PROFILE_DIR="${PROFILE_DIR:-/tmp/tracepod-fixtures-profiles}"
KEEP_CLUSTER=false
ARCH=$(uname -m)

# Schema version drives the fixtures subdirectory. Default: read the integer
# constant the sensor emits so the directory always matches the wire version.
SCHEMA_VERSION="${SCHEMA_VERSION:-$(cd "${REPO_ROOT}" && go run ./hack/schemaversion 2>/dev/null || echo 2)}"
FIXTURE_DIR="${FIXTURE_DIR:-${REPO_ROOT}/testdata/profile-fixtures/v${SCHEMA_VERSION}}"

# ── Pinned workload images (by digest — determinism) ────────────────────────────
# Resolved with `crane digest <ref>` / `docker manifest inspect`. To refresh,
# update these and re-record. Keep the human-readable tag in the comment.
# All three are multi-arch (linux/amd64 + linux/arm64) so the recorder is
# reproducible on both the arm64 Lima VM and the amd64 CI runner.
STATIC_IMAGE="${STATIC_IMAGE:-traefik/whoami@sha256:1699d99cb4b9acc17f74ca670b3d8d0b7ba27c948b3445f0593b58ebece92f04}"        # v1.10.4 (static Go binary)
INTERP_IMAGE="${INTERP_IMAGE:-python@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203}"               # 3.12-slim
RESTART_IMAGE="${RESTART_IMAGE:-busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"            # 1.36

for arg in "$@"; do
  case "$arg" in
    --keep-cluster) KEEP_CLUSTER=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[fixtures]${NC} $*"; }
warn()  { echo -e "${YELLOW}[fixtures]${NC} $*"; }
fail()  { echo -e "${RED}[fixtures FAIL]${NC} $*" >&2; }

cleanup() {
  if [ "$KEEP_CLUSTER" = true ]; then
    warn "--keep-cluster set; leaving ${CLUSTER_NAME} up"
    return
  fi
  info "Cleaning up..."
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  rm -rf "${PROFILE_DIR}" /tmp/tracepod-fixtures-kubeconfig.yaml 2>/dev/null || true
}
trap cleanup EXIT

# ── Phase 0: prerequisites ──────────────────────────────────────────────────────
info "Phase 0: checking prerequisites (arch: ${ARCH}, schema v${SCHEMA_VERSION})"
for cmd in docker kind kubectl helm go jq; do
  command -v "$cmd" >/dev/null 2>&1 || { fail "required tool not found: $cmd"; exit 1; }
done

# ── Phase 1: sensor image ───────────────────────────────────────────────────────
info "Phase 1: building sensor image ${SENSOR_IMAGE}"
cd "${REPO_ROOT}"
if docker image inspect "${SENSOR_IMAGE}" >/dev/null 2>&1; then
  info "Sensor image already present — skipping build"
elif [ "${ARCH}" = "aarch64" ]; then
  docker build --platform linux/arm64 -f Dockerfile.sensor -t "${SENSOR_IMAGE}" .
else
  [ -f "${REPO_ROOT}/sensor" ] || { fail "amd64: pre-build ./sensor first (make generate && go build -o sensor ./cmd/sensor)"; exit 1; }
  docker build -f Dockerfile.sensor.dev -t "${SENSOR_IMAGE}" .
fi

# ── Phase 2: kind + sensor ──────────────────────────────────────────────────────
info "Phase 2: kind cluster + sensor DaemonSet"
mkdir -p "${PROFILE_DIR}"

# Generate a kind config whose extraMount maps the node's profile hostPath to OUR
# PROFILE_DIR (the static e2e config hardcodes a different host path). NRI is
# enabled so the sensor receives container lifecycle events.
KIND_CONFIG="${PROFILE_DIR}/kind-config.yaml"
cat > "${KIND_CONFIG}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |
    [plugins."io.containerd.nri.v1.nri"]
      disable = false
      socket_path = "/var/run/nri/nri.sock"
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: ${PROFILE_DIR}
        containerPath: /var/lib/tracepod/profiles
EOF

kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$" || \
  kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
kind get kubeconfig --name "${CLUSTER_NAME}" > /tmp/tracepod-fixtures-kubeconfig.yaml
export KUBECONFIG=/tmp/tracepod-fixtures-kubeconfig.yaml
kind load docker-image "${SENSOR_IMAGE}" --name "${CLUSTER_NAME}"

# ── Phase 2b: missed-start workload (deployed BEFORE the sensor) ─────────────────
# This container is already running when the sensor registers, so the sensor
# adopts it via NRI Synchronize → process_start_observed=false. This is the
# deliberate R2 missed-start fixture.
info "Phase 2b: deploying missed-start workload (before sensor)"
kubectl create deployment fx-missed --image="${RESTART_IMAGE}" -- \
  /bin/sh -c "echo missed-start; sleep 3600" >/dev/null
kubectl rollout status deployment/fx-missed --timeout=90s

# ── Phase 3: sensor + live workloads ────────────────────────────────────────────
info "Phase 3: deploying sensor (adopts fx-missed via Synchronize)"
helm upgrade --install tracepod "${REPO_ROOT}/helm/tracepod" \
  --set sensor.image.repository="${SENSOR_IMAGE%%:*}" \
  --set sensor.image.tag="${SENSOR_IMAGE##*:}" \
  --set sensor.image.pullPolicy=Never \
  --set sensor.profileHostPath=/var/lib/tracepod/profiles
kubectl rollout status daemonset/tracepod-sensor --timeout=120s

info "Phase 3: deploying live workloads (sensor attaches via StartContainer)"
# static: fast-saturating static Go binary (whoami listens on :80, default cmd).
kubectl create deployment fx-static --image="${STATIC_IMAGE}" >/dev/null
# interp: interpreted app — opens many shared libraries at import time.
kubectl create deployment fx-interp --image="${INTERP_IMAGE}" -- \
  python -c "import json,ssl,hashlib,sqlite3; import time; time.sleep(3600)" >/dev/null
# restart: exits quickly; the Deployment restarts it, producing multiple starts.
kubectl create deployment fx-restart --image="${RESTART_IMAGE}" -- \
  /bin/sh -c "echo up; sleep 4; exit 0" >/dev/null

kubectl rollout status deployment/fx-static --timeout=90s || true
kubectl rollout status deployment/fx-interp --timeout=90s || true

# Accumulate the container IDs that belong to OUR workloads (current generation
# plus any restarted generations via lastState.terminated) so collection can
# filter out system pods the sensor also profiles. Map each ID → fixture name.
declare -A IDMAP
declare -A FIXNAME=( [fx-static]=static [fx-interp]=interp [fx-restart]=restart [fx-missed]=missed-start )
collect_ids() {
  for dep in fx-static fx-interp fx-restart fx-missed; do
    while IFS= read -r raw; do
      id="${raw#containerd://}"
      [ -z "$id" ] && continue
      IDMAP["$id"]="${FIXNAME[$dep]}"
    done < <(kubectl get pods -l app="$dep" \
      -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.containerID}{"\n"}{.lastState.terminated.containerID}{"\n"}{end}{end}' 2>/dev/null)
  done
}

info "Letting workloads run and (for fx-restart) restart a few times..."
for _ in $(seq 1 14); do collect_ids; sleep 3; done   # ~42s window, polling for restarts

info "Stopping workloads to flush profiles..."
kubectl scale deployment fx-static fx-interp fx-restart fx-missed --replicas=0
collect_ids

info "Captured ${#IDMAP[@]} container ID(s) across our workloads"

# ── Phase 4: collect (filtered to our workloads, named by fixture) ──────────────
info "Phase 4: collecting profiles into ${FIXTURE_DIR}"
rm -rf "${FIXTURE_DIR}"
mkdir -p "${FIXTURE_DIR}"

# Wait until profiles for (most of) our captured IDs have been flushed to disk.
for _ in $(seq 1 30); do
  have=0
  for id in "${!IDMAP[@]}"; do
    [ -f "${PROFILE_DIR}/${id}/files.json" ] && have=$((have + 1))
  done
  [ "$have" -ge "${#IDMAP[@]}" ] && break
  sleep 2
done

# Counters per fixture name, so multiple generations (fx-restart) get -N suffixes.
declare -A NAMECOUNT
count=0
for id in "${!IDMAP[@]}"; do
  f="${PROFILE_DIR}/${id}/files.json"
  [ -f "$f" ] || { warn "no profile on disk for ${IDMAP[$id]} container ${id:0:12}"; continue; }
  ver=$(jq -r '.schema_version' "$f")
  if [ "$ver" != "${SCHEMA_VERSION}" ]; then
    warn "skipping ${id:0:12}: schema_version=${ver} != ${SCHEMA_VERSION}"; continue
  fi
  name="${IDMAP[$id]}"
  NAMECOUNT[$name]=$(( ${NAMECOUNT[$name]:-0} + 1 ))
  if [ "${NAMECOUNT[$name]}" -gt 1 ]; then
    out="${name}-${NAMECOUNT[$name]}.json"
  else
    out="${name}.json"
  fi
  cp "$f" "${FIXTURE_DIR}/${out}"
  count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
  fail "no profiles recorded — sensor produced nothing for our workloads"
  exit 1
fi

# Record provenance (NOT a profile fixture — metadata about the recording).
cat > "${FIXTURE_DIR}/RECORDING.md" <<EOF
# Recorded profile fixtures — schema v${SCHEMA_VERSION}

Recorded by hack/record-profile-fixtures.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
(arch: ${ARCH}). Verbatim sensor output — do not edit by hand; re-record instead.

Workloads (pinned by digest):
- static (whoami):  ${STATIC_IMAGE}
- interp (python):  ${INTERP_IMAGE}
- restart/missed (busybox): ${RESTART_IMAGE}

Fixtures (one profile per profiled container; restart generations suffixed -N):
- static.json       fast-saturating static binary — process_start_observed: true
- interp.json       interpreted app, large shared-library surface — true
- restart*.json     restarted in-window; each generation a separate profile — true
- missed-start.json deployed BEFORE the sensor, adopted via Synchronize — false

Note: container IDs differ on every re-record; the marker outcomes above and the
pinned images are the stable, replay-relevant properties.
EOF

info "Recorded ${count} profile fixture(s):"
ls -1 "${FIXTURE_DIR}"
info "marker summary:"
for f in "${FIXTURE_DIR}"/*.json; do
  printf "  %-20s pso=%s starts=%s files=%s\n" "$(basename "$f")" \
    "$(jq -r '.coverage.process_start_observed' "$f")" \
    "$(jq -r '.container_starts|length' "$f")" \
    "$(jq -r '.files|length' "$f")"
done

echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}  fixtures recorded → ${FIXTURE_DIR}${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}"
