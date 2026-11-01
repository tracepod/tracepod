#!/usr/bin/env bash
# run-snapshot-e2e.sh — focused end-to-end test for the sensor's interim
# profile snapshots (--snapshot-interval).
#
# Starts a kind cluster, runs a tiny HTTP receiver on the host that logs every
# POST the sensor makes to --controller-url, and checks two scenarios:
#
#   1. sensor.snapshotInterval=10s: an nginx Deployment runs ~40s, then is
#      stopped. Expect >=2 interim POSTs (profile_terminal=false, identical
#      container_id and profile_start, non-decreasing file counts and
#      profile_end) followed by exactly ONE terminal POST, which is last.
#   2. flag off (default): the same workload produces exactly ONE POST, the
#      terminal one.
#
# Usage:
#   bash hack/e2e/run-snapshot-e2e.sh [--keep-cluster]
#
# Environment variables:
#   SENSOR_IMAGE   sensor image (default: tracepod-sensor:snapshot-e2e). Built
#                  from Dockerfile.sensor if absent — `docker rmi` it first to
#                  test fresh code.
#   CLUSTER_NAME   kind cluster name (default: tracepod-snapshot-e2e)
#   RECEIVER_PORT  host port for the receiver (default: 18080)
#   RUN_SECONDS    how long the workload runs before stopping (default: 40)
#
# Requires: docker, kind, kubectl, helm, jq, python3. arm64 hosts (the Lima VM)
# build from the committed arm64 BPF objects; on amd64 a pre-built ./sensor
# binary is used (see run-e2e.sh Phase 1). Does not touch other kind clusters.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SENSOR_IMAGE="${SENSOR_IMAGE:-tracepod-sensor:snapshot-e2e}"
CLUSTER_NAME="${CLUSTER_NAME:-tracepod-snapshot-e2e}"
RECEIVER_PORT="${RECEIVER_PORT:-18080}"
RUN_SECONDS="${RUN_SECONDS:-40}"
ARCH=$(uname -m)
KEEP_CLUSTER=false
WORKDIR="$(mktemp -d)"
RECEIVER_LOG="${WORKDIR}/posts.jsonl"
RECEIVER_PID=""

for arg in "$@"; do
  case "$arg" in
    --keep-cluster) KEEP_CLUSTER=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

info() { echo "[snapshot-e2e] $*"; }
fail() { echo "[snapshot-e2e FAIL] $*" >&2; }

cleanup() {
  local rc=$?
  if [ $rc -ne 0 ]; then
    fail "failed — sensor logs:"
    KUBECONFIG="${WORKDIR}/kubeconfig" kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=60 2>/dev/null || true
    fail "receiver log:"; cat "${RECEIVER_LOG}" 2>/dev/null || true
  fi
  [ -n "${RECEIVER_PID}" ] && kill "${RECEIVER_PID}" 2>/dev/null || true
  if [ "$KEEP_CLUSTER" = true ]; then
    info "--keep-cluster set; leaving cluster ${CLUSTER_NAME} (work dir ${WORKDIR})"
  else
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

for cmd in docker kind kubectl helm jq python3; do
  command -v "$cmd" >/dev/null 2>&1 || { fail "required tool not found: $cmd"; exit 1; }
done

# ── Receiver: logs one JSON line per POST, answers 201 like the real endpoint ──
cat > "${WORKDIR}/receiver.py" <<'PY'
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[2]

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            m = json.loads(body)
            rec = {
                "recv": time.time(),
                "path": self.path.split("?")[0],
                "container_id": m.get("container_id"),
                "profile_start": m.get("profile_start"),
                "profile_end": m.get("profile_end"),
                "terminal": m.get("profile_terminal"),
                "files": len(m.get("files") or {}),
            }
            with open(LOG, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception as e:  # keep serving; the assertions will notice
            sys.stderr.write("bad body: %s\n" % e)
        self.send_response(201)
        self.end_headers()
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
: > "${RECEIVER_LOG}"
python3 "${WORKDIR}/receiver.py" "${RECEIVER_PORT}" "${RECEIVER_LOG}" &
RECEIVER_PID=$!

# ── Sensor image ────────────────────────────────────────────────────────────────
cd "${REPO_ROOT}"
if docker image inspect "${SENSOR_IMAGE}" >/dev/null 2>&1; then
  info "reusing existing image ${SENSOR_IMAGE} (docker rmi it to test fresh code)"
elif [ "${ARCH}" = "aarch64" ]; then
  docker build --platform linux/arm64 -f Dockerfile.sensor -t "${SENSOR_IMAGE}" .
else
  [ -f "${REPO_ROOT}/sensor" ] || { fail "amd64: build ./sensor first (make generate && CGO_ENABLED=0 go build -o sensor ./cmd/sensor)"; exit 1; }
  docker build -f Dockerfile.sensor.dev -t "${SENSOR_IMAGE}" .
fi

# ── kind cluster (its own name; the NRI-enabled config is shared with run-e2e) ──
# The config's extraMounts need the host path to exist; it is unused here
# because the sensor posts to the receiver instead of writing profiles.
mkdir -p /tmp/tracepod-e2e-profiles
sed "s/^name: .*/name: ${CLUSTER_NAME}/" "${SCRIPT_DIR}/kind-config.yaml" > "${WORKDIR}/kind-config.yaml"
kind create cluster --name "${CLUSTER_NAME}" --config "${WORKDIR}/kind-config.yaml"
kind get kubeconfig --name "${CLUSTER_NAME}" > "${WORKDIR}/kubeconfig"
export KUBECONFIG="${WORKDIR}/kubeconfig"
kubectl wait --for=condition=Ready node --all --timeout=120s
kind load docker-image "${SENSOR_IMAGE}" --name "${CLUSTER_NAME}"

# Host address as seen from pods: the kind docker network's IPv4 gateway.
GW=$(docker network inspect kind -f '{{range .IPAM.Config}}{{println .Gateway}}{{end}}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
[ -n "${GW}" ] || { fail "could not determine kind network gateway"; exit 1; }
CONTROLLER_URL="http://${GW}:${RECEIVER_PORT}"
info "receiver reachable from pods at ${CONTROLLER_URL}"

install_sensor() {  # $1 = snapshotInterval ("" = flag off)
  local extra=()
  [ -n "$1" ] && extra+=(--set "sensor.snapshotInterval=$1")
  helm upgrade --install tracepod "${REPO_ROOT}/helm/tracepod" \
    --set sensor.image.repository="${SENSOR_IMAGE%%:*}" \
    --set sensor.image.tag="${SENSOR_IMAGE##*:}" \
    --set sensor.image.pullPolicy=Never \
    --set sensor.controllerURL="${CONTROLLER_URL}" \
    "${extra[@]}"
  kubectl rollout restart daemonset/tracepod-sensor >/dev/null
  # Wait until the *new* pod reports NRI connected (poll: rollout status can
  # pass vacuously before the DaemonSet controller has scheduled anything).
  for _ in $(seq 1 60); do
    if kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 2>/dev/null | grep -q "NRI connected"; then
      if [ -n "$1" ]; then
        kubectl logs -l app.kubernetes.io/name=tracepod-sensor --tail=-1 | grep -q "interim snapshots enabled every" && return 0
      else
        return 0
      fi
    fi
    sleep 2
  done
  fail "sensor not ready (NRI connected${1:+ + snapshots enabled})"; return 1
}

run_workload() {  # $1 = deployment name
  kubectl create deployment "$1" --image=nginx:alpine >/dev/null
  kubectl rollout status "deployment/$1" --timeout=90s
  info "$1 running; waiting ${RUN_SECONDS}s"
  sleep "${RUN_SECONDS}"
  kubectl scale "deployment/$1" --replicas=0 >/dev/null
  # Let the stop-time POST land.
  for _ in $(seq 1 30); do
    jq -e --arg p "/internal/profiles/default/$1" 'select(.path==$p) | select(.terminal==true)' "${RECEIVER_LOG}" >/dev/null 2>&1 && break
    sleep 2
  done
  sleep 3  # ensure nothing trails the terminal POST
}

posts_for() {  # $1 = deployment name → JSON array of its POSTs in arrival order
  jq -s --arg p "/internal/profiles/default/$1" '[.[] | select(.path==$p)]' "${RECEIVER_LOG}"
}

# ── Scenario 1: --snapshot-interval=10s ────────────────────────────────────────
info "scenario 1: sensor.snapshotInterval=10s"
install_sensor 10s
run_workload snap-on
ON=$(posts_for snap-on)
echo "${ON}" | jq -c '.[] | {t:(.recv|floor), terminal, files, profile_start, profile_end}'

N=$(echo "${ON}" | jq 'length')
INTERIM=$(echo "${ON}" | jq '[.[] | select(.terminal==false)] | length')
TERMINALS=$(echo "${ON}" | jq '[.[] | select(.terminal==true)] | length')
[ "${INTERIM}" -ge 2 ] || { fail "want >=2 interim POSTs, got ${INTERIM}"; exit 1; }
[ "${TERMINALS}" -eq 1 ] || { fail "want exactly 1 terminal POST, got ${TERMINALS}"; exit 1; }
[ "$(echo "${ON}" | jq '.[-1].terminal')" = "true" ] || { fail "terminal POST is not last"; exit 1; }
[ "$(echo "${ON}" | jq '[.[].container_id] | unique | length')" -eq 1 ] || { fail "container_id changed between POSTs"; exit 1; }
[ "$(echo "${ON}" | jq '[.[].profile_start] | unique | length')" -eq 1 ] || { fail "profile_start changed between POSTs"; exit 1; }
echo "${ON}" | jq -e '[.[].files] as $f | [range(1; $f|length) | $f[.] >= $f[.-1]] | all' >/dev/null \
  || { fail "file counts decreased between POSTs"; exit 1; }
echo "${ON}" | jq -e '[.[].profile_end] as $e | [range(1; $e|length) | $e[.] >= $e[.-1]] | all' >/dev/null \
  || { fail "profile_end went backwards"; exit 1; }
info "scenario 1 OK: ${INTERIM} interim POST(s) then 1 terminal (total ${N})"

# ── Scenario 2: flag off ────────────────────────────────────────────────────────
info "scenario 2: flag off"
install_sensor ""
run_workload snap-off
OFF=$(posts_for snap-off)
echo "${OFF}" | jq -c '.[] | {t:(.recv|floor), terminal, files}'
[ "$(echo "${OFF}" | jq 'length')" -eq 1 ] || { fail "flag off: want exactly 1 POST, got $(echo "${OFF}" | jq 'length')"; exit 1; }
[ "$(echo "${OFF}" | jq '.[0].terminal')" = "true" ] || { fail "flag off: the single POST is not terminal"; exit 1; }
info "scenario 2 OK: exactly one terminal POST"

info "PASS"
