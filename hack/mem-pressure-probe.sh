#!/usr/bin/env bash
# mem-pressure-probe.sh — OSS-4b diagnostic (NOT part of CI).
#
# Answers the open question behind the event_loss.tolerated category: does the
# openat path-read fault (event_loss.tolerated.path_read_failed) scale under
# MEMORY pressure? The idle floor is 0-2 per container-window; the fault is a
# user page that was not present when bpf_probe_read_user_str() ran, so memory
# pressure (page reclaim / thrash) is exactly the condition under which it might
# grow. This script measures path_read_failed for the SAME file-open storm under
# the DEFAULT 256 KB ring buffer (so bpf_reserve_failed stays ~0 and path-read
# faults are isolated), once at rest and once under a stress-ng --vm neighbour.
#
# Output: path_read_failed (and bpf_reserve_failed, which should remain ~0) for
# each phase, so the consumer's default ceiling can be informed by real numbers.
#
# Usage (inside the k8s-dev Lima VM, repo root):
#   bash hack/mem-pressure-probe.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SENSOR_IMAGE="${SENSOR_IMAGE:-tracepod-sensor:fixtures}"
CLUSTER_NAME="${CLUSTER_NAME:-tracepod-mempressure}"
PROFILE_DIR="${PROFILE_DIR:-/tmp/tracepod-mempressure-profiles}"
RESTART_IMAGE="${RESTART_IMAGE:-busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
# stress-ng footprint. 6 GiB VM. Pushed high enough to force genuine page reclaim
# (available → a few hundred MB) without OOM-killing the kind node/sensor.
VM_WORKERS="${VM_WORKERS:-3}"
VM_BYTES="${VM_BYTES:-1700M}"
STORM_SECONDS="${STORM_SECONDS:-60}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[mem-probe]${NC} $*"; }
warn() { echo -e "${YELLOW}[mem-probe]${NC} $*"; }

cleanup() {
  info "cleanup"
  pkill -f 'stress-ng' 2>/dev/null || true
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  rm -rf "${PROFILE_DIR}" /tmp/tracepod-mempressure-kubeconfig.yaml 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "${PROFILE_DIR}"
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

info "creating kind cluster ${CLUSTER_NAME}"
kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
kind get kubeconfig --name "${CLUSTER_NAME}" > /tmp/tracepod-mempressure-kubeconfig.yaml
export KUBECONFIG=/tmp/tracepod-mempressure-kubeconfig.yaml
kind load docker-image "${SENSOR_IMAGE}" --name "${CLUSTER_NAME}"

info "deploying sensor (DEFAULT 256 KB ring buffer)"
helm upgrade --install tracepod "${REPO_ROOT}/helm/tracepod" \
  --set sensor.image.repository="${SENSOR_IMAGE%%:*}" \
  --set sensor.image.tag="${SENSOR_IMAGE##*:}" \
  --set sensor.image.pullPolicy=Never \
  --set sensor.profileHostPath=/var/lib/tracepod/profiles
kubectl rollout status daemonset/tracepod-sensor --timeout=120s
sleep 5

# Sum a profile field across all container IDs of a deployment (current + restarted).
sum_field() {  # $1 = deployment label, $2 = jq path
  local dep="$1" path="$2" total=0 v
  declare -A ids
  for _ in $(seq 1 5); do
    while IFS= read -r raw; do
      id="${raw#containerd://}"; [ -z "$id" ] && continue; ids["$id"]=1
    done < <(kubectl get pods -l app="$dep" \
      -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.containerID}{"\n"}{.lastState.terminated.containerID}{"\n"}{end}{end}' 2>/dev/null)
    sleep 1
  done
  for id in "${!ids[@]}"; do
    local f="${PROFILE_DIR}/${id}/files.json"
    [ -f "$f" ] || continue
    v=$(jq -r "${path} // 0" "$f")
    total=$((total + v))
  done
  echo "$total"
}

run_storm() {  # $1 = deployment name
  kubectl create deployment "$1" --image="${RESTART_IMAGE}" -- \
    /bin/sh -c 'while true; do for i in 1 2 3 4 5 6 7 8; do ( ls -laR /proc /etc /bin /usr /lib 2>/dev/null >/dev/null ) & done; wait; done' >/dev/null
  kubectl rollout status deployment/"$1" --timeout=90s || true
}

# Validate capture: wait until at least one profile for the deployment is flushed
# with files>0, so a reported 0 is a true zero and not a missed flush. Prints the
# captured files-count (sanity that the storm was actually observed).
wait_profiles() {  # $1 = deployment label
  local dep="$1" files
  for _ in $(seq 1 30); do
    files=$(sum_field "$dep" '.files|length')
    [ "${files:-0}" -gt 0 ] && { echo "$files"; return 0; }
    sleep 2
  done
  echo 0
}

# ── Phase A: baseline (no memory pressure) ──────────────────────────────────────
info "Phase A: file-open storm at rest for ${STORM_SECONDS}s"
free -m | awk 'NR==1||/Mem/{print "  "$0}'
run_storm fx-mp-base
sleep "${STORM_SECONDS}"
kubectl scale deployment fx-mp-base --replicas=0 >/dev/null
BASE_FILES=$(wait_profiles fx-mp-base)
BASE_PR=$(sum_field fx-mp-base '.event_loss.tolerated.path_read_failed')
BASE_RES=$(sum_field fx-mp-base '.event_loss.by_stage.bpf_reserve_failed')
info "Phase A result: path_read_failed=${BASE_PR}  bpf_reserve_failed=${BASE_RES}  (captured files=${BASE_FILES})"

# ── Phase B: under memory pressure ──────────────────────────────────────────────
info "Phase B: starting stress-ng --vm ${VM_WORKERS} --vm-bytes ${VM_BYTES} --vm-keep"
stress-ng --vm "${VM_WORKERS}" --vm-bytes "${VM_BYTES}" --vm-keep \
  --timeout $((STORM_SECONDS + 30))s >/tmp/stress-ng.log 2>&1 &
STRESS_PID=$!
sleep 5
free -m | awk 'NR==1||/Mem/{print "  "$0}'
info "Phase B: file-open storm under pressure for ${STORM_SECONDS}s"
run_storm fx-mp-stress
sleep "${STORM_SECONDS}"
free -m | awk 'NR==1||/Mem/{print "  "$0}'
kubectl scale deployment fx-mp-stress --replicas=0 >/dev/null
STRESS_FILES=$(wait_profiles fx-mp-stress)
kill "${STRESS_PID}" 2>/dev/null || true
STRESS_PR=$(sum_field fx-mp-stress '.event_loss.tolerated.path_read_failed')
STRESS_RES=$(sum_field fx-mp-stress '.event_loss.by_stage.bpf_reserve_failed')
info "Phase B result: path_read_failed=${STRESS_PR}  bpf_reserve_failed=${STRESS_RES}  (captured files=${STRESS_FILES})"

echo
echo "════════════════ MEMORY-PRESSURE PROBE RESULT ════════════════"
printf "  %-28s baseline=%-10s under-pressure=%s\n" "tolerated.path_read_failed" "${BASE_PR}" "${STRESS_PR}"
printf "  %-28s baseline=%-10s under-pressure=%s\n" "by_stage.bpf_reserve_failed" "${BASE_RES}" "${STRESS_RES}"
printf "  %-28s baseline=%-10s under-pressure=%s\n" "(captured files, sanity)" "${BASE_FILES}" "${STRESS_FILES}"
echo "  (default 256 KB ring buffer; storm=${STORM_SECONDS}s each; stress-ng --vm ${VM_WORKERS} --vm-bytes ${VM_BYTES})"
echo "═══════════════════════════════════════════════════════════════"
