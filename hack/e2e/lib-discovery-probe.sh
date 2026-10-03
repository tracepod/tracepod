#!/usr/bin/env bash
# lib-discovery-probe.sh — shared helper for exercising hack/discovery-probe.sh
# against a live kind node exactly the way a user without node/SSH access
# would: through a `kubectl debug node` pod. Sourced by hack/e2e/run-e2e.sh
# (positive path: NRI enabled, opt-in via PROBE_VIA_DEBUG_POD=true so it never
# runs in the AL2023 legs that reuse that script) and by
# hack/e2e/run-e2e-no-nri.sh (negative path: NRI disabled).
#
# Requires $REPO_ROOT, and the caller's own `info`/`fail` log helpers.

# run_discovery_probe_via_debug_pod <node> <want_exit>
#
# Ships THIS CHECKOUT's hack/discovery-probe.sh into a fresh `kubectl debug
# node` pod via `kubectl cp` (not curled from GitHub — this exercises the PR's
# own version), runs it with HOST_ROOT=/host (the debug pod's own /sys and
# /proc reflect the pod, not the host — see the script's header), and asserts
# its exit code equals <want_exit>. Always tears down the debug pod. Prints
# the probe's full output either way for debugging.
run_discovery_probe_via_debug_pod() {
  local node="$1" want_exit="$2"

  # `kubectl debug node` generates its own pod name (node-debugger-<node>-<rand>)
  # — it does not take a --name for the POD itself (only for the container), so
  # the generated name is parsed back out of the command's own "Creating
  # debugging pod ..." stdout message rather than assumed.
  info "discovery-probe: creating a debug pod on node ${node}..."
  local create_out
  if ! create_out=$(kubectl debug "node/${node}" --image=ubuntu:24.04 -- sleep 300 2>&1); then
    fail "discovery-probe: 'kubectl debug node/${node}' failed: ${create_out}"
    return 1
  fi
  echo "${create_out}" | sed 's/^/        /'
  local pod
  pod=$(echo "${create_out}" | grep -oE 'node-debugger-[A-Za-z0-9.-]+' | head -1)
  if [ -z "${pod}" ]; then
    fail "discovery-probe: could not parse debug pod name from kubectl debug output above"
    return 1
  fi

  local phase=""
  for _ in $(seq 1 30); do
    phase=$(kubectl get pod "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "${phase}" = "Running" ] && break
    sleep 2
  done
  if [ "${phase}" != "Running" ]; then
    fail "discovery-probe: debug pod ${pod} never reached Running (last phase: ${phase:-unknown})"
    kubectl describe pod "${pod}" 2>/dev/null | sed 's/^/        /' || true
    kubectl delete pod "${pod}" --now --ignore-not-found >/dev/null 2>&1 || true
    return 1
  fi

  kubectl cp "${REPO_ROOT}/hack/discovery-probe.sh" "${pod}:/tmp/discovery-probe.sh"

  local out rc
  set +e
  out=$(kubectl exec "${pod}" -- bash -c '
    for i in 1 2 3; do
      apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq socat >/dev/null 2>&1 && break
      sleep 3
    done
    HOST_ROOT=/host bash /tmp/discovery-probe.sh
  ' 2>&1)
  rc=$?
  set -e

  echo "${out}" | sed 's/^/        [discovery-probe] /'
  kubectl delete pod "${pod}" --now --ignore-not-found >/dev/null 2>&1 || true

  if [ "${rc}" -ne "${want_exit}" ]; then
    fail "discovery-probe via debug pod: exit ${rc}, want ${want_exit}"
    return 1
  fi
  info "discovery-probe via debug pod: exit ${rc} (expected)"
  return 0
}
