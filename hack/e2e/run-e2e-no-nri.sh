#!/usr/bin/env bash
# run-e2e-no-nri.sh — negative-path e2e: deploy the sensor DaemonSet into a
# kind cluster with NRI explicitly disabled, and assert it REFUSES to run
# (CrashLoopBackOff, not Ready, "NRI unavailable" in its logs) instead of
# quietly tracing nothing. Also exercises hack/discovery-probe.sh via a
# node-debug pod against the same cluster, asserting it reports exit 1.
#
# Sensor-only — no nginx workload, no harden/validate/SBOM phases — so this
# runs in a couple of minutes next to the full positive-path run-e2e.sh.
#
# Usage:
#   SENSOR_IMAGE=tracepod-sensor:e2e bash hack/e2e/run-e2e-no-nri.sh [--keep-cluster]
#
#   --keep-cluster   Skip kind cluster deletion on exit (useful for debugging).
#
# Environment variables:
#   SENSOR_IMAGE   Docker image for the sensor (default: tracepod-sensor:e2e;
#                  must already exist — this script does not build it, see
#                  hack/e2e/run-e2e.sh Phase 1 for how)
#   CLUSTER_NAME   kind cluster name (default: tracepod-e2e-no-nri)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SENSOR_IMAGE="${SENSOR_IMAGE:-tracepod-sensor:e2e}"
CLUSTER_NAME="${CLUSTER_NAME:-tracepod-e2e-no-nri}"
KEEP_CLUSTER=false

for arg in "$@"; do
  case "$arg" in
    --keep-cluster) KEEP_CLUSTER=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[e2e-no-nri]${NC} $*"; }
warn()  { echo -e "${YELLOW}[e2e-no-nri]${NC} $*"; }
fail()  { echo -e "${RED}[e2e-no-nri FAIL]${NC} $*" >&2; }

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    fail "e2e-no-nri failed — collecting debug info"
    kubectl get pods -A -o wide 2>/dev/null || true
    kubectl describe pods -l app.kubernetes.io/name=tracepod-sensor 2>/dev/null || true
    echo "=== sensor logs (current) ==="
    kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 2>/dev/null || true
    echo "=== sensor logs (--previous) ==="
    kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 --previous 2>/dev/null || true
  fi
  if [ "$KEEP_CLUSTER" = true ]; then
    warn "--keep-cluster set; skipping teardown (cluster: ${CLUSTER_NAME})"
    return
  fi
  info "Cleaning up..."
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Phase 0: prerequisites ──────────────────────────────────────────────────────
info "Phase 0: checking prerequisites"
for cmd in docker kind kubectl helm; do
  command -v "$cmd" >/dev/null 2>&1 || { fail "required tool not found: $cmd"; exit 1; }
done
if ! docker image inspect "${SENSOR_IMAGE}" >/dev/null 2>&1; then
  fail "sensor image ${SENSOR_IMAGE} not found — build it first (see hack/e2e/run-e2e.sh Phase 1)"
  exit 1
fi

# ── Phase 1: kind cluster (NRI explicitly disabled) ─────────────────────────────
info "Phase 1: creating kind cluster '${CLUSTER_NAME}' (NRI explicitly disabled)"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  warn "Cluster '${CLUSTER_NAME}' already exists — reusing"
else
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${SCRIPT_DIR}/kind-config-no-nri.yaml"
fi

kind get kubeconfig --name "${CLUSTER_NAME}" > /tmp/tracepod-e2e-no-nri-kubeconfig.yaml
export KUBECONFIG=/tmp/tracepod-e2e-no-nri-kubeconfig.yaml

info "Waiting for kind node to be Ready (up to 120s)..."
kubectl wait --for=condition=Ready node --all --timeout=120s

kind load docker-image "${SENSOR_IMAGE}" --name "${CLUSTER_NAME}"

# ── Phase 2: sensor-only Helm install ────────────────────────────────────────────
info "Phase 2: deploying tracepod sensor via Helm (sensor only — no workload needed)"
helm upgrade --install tracepod "${REPO_ROOT}/helm/tracepod" \
  --set sensor.image.repository="${SENSOR_IMAGE%%:*}" \
  --set sensor.image.tag="${SENSOR_IMAGE##*:}" \
  --set sensor.image.pullPolicy=Never \
  --set sensor.profileHostPath=/var/lib/tracepod/profiles

# ── Phase 3: assert the sensor refuses to run ───────────────────────────────────
info "Phase 3: asserting the sensor refuses to run (up to 120s)..."
REFUSED=false
RESTARTS=0
EXITCODE=""
READY=""
for i in $(seq 1 60); do
  RESTARTS=$(kubectl get pods -l app.kubernetes.io/name=tracepod-sensor \
    -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null || true)
  EXITCODE=$(kubectl get pods -l app.kubernetes.io/name=tracepod-sensor \
    -o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated.exitCode}' 2>/dev/null || true)
  READY=$(kubectl get pods -l app.kubernetes.io/name=tracepod-sensor \
    -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || true)
  RESTARTS="${RESTARTS:-0}"

  if [ "${RESTARTS}" -ge 1 ] 2>/dev/null && [ "${READY}" != "true" ]; then
    REFUSED=true
    info "sensor pod restartCount=${RESTARTS} lastExitCode=${EXITCODE:-unknown} ready=${READY:-false}"
    break
  fi
  echo -n "."
  sleep 2
done
echo
if [ "$REFUSED" != true ]; then
  fail "sensor pod never showed restartCount>=1 with ready!=true within 120s (last: restarts=${RESTARTS} ready=${READY:-unknown})"
  exit 1
fi
if [ -n "${EXITCODE:-}" ] && [ "${EXITCODE}" != "1" ]; then
  fail "sensor container's last exit code was ${EXITCODE}, want 1"
  exit 1
fi
info "sensor container's last exit code: ${EXITCODE:-unknown} (want 1 — OK)"

# ── Phase 4: assert the logs explain why ────────────────────────────────────────
info "Phase 4: asserting the logs mention 'NRI unavailable'..."
LOGS=$(kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 2>/dev/null || true)
PREV_LOGS=$(kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 --previous 2>/dev/null || true)
if [[ "$LOGS" != *"NRI unavailable"* ]] && [[ "$PREV_LOGS" != *"NRI unavailable"* ]]; then
  fail "neither current nor --previous sensor logs mention 'NRI unavailable'"
  echo "--- current logs ---"; echo "$LOGS"
  echo "--- previous logs ---"; echo "$PREV_LOGS"
  exit 1
fi
info "Found 'NRI unavailable' in sensor logs:"
{ echo "$LOGS"; echo "$PREV_LOGS"; } | grep "NRI unavailable" | tail -1 | sed 's/^/        /'

# ── Phase 5: discovery-probe.sh agrees, via a node-debug pod ────────────────────
info "Phase 5: discovery-probe via node-debug pod (NRI disabled — expect exit 1)"
# shellcheck source=hack/e2e/lib-discovery-probe.sh
source "${SCRIPT_DIR}/lib-discovery-probe.sh"
NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
if ! run_discovery_probe_via_debug_pod "${NODE}" 1; then
  exit 1
fi

info "PASS: sensor refuses to run without NRI, and discovery-probe.sh agrees"
