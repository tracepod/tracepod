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
