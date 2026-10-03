#!/usr/bin/env bash
# run-e2e-al2023.sh — run hack/e2e/run-e2e.sh inside the al2023-e2e Lima VM.
#
# This VM has no host mounts (see infra/lima/al2023-e2e.yaml), so the repo
# source is shipped in as a tarball via `limactl copy` rather than mounted.
# The VM shares the HOST kernel with kind's containers, so this exercises the
# full product pipeline (sensor, harden, sandbox validation) against Amazon
# Linux 2023's own kernel build — not just BPF load/attach as
# hack/kernel-compat.sh does.
#
# Usage (run on the Mac host, from the repo root):
#   hack/e2e/run-e2e-al2023.sh [--kernel 6.1|6.12|6.18] [--ref <tag-or-commit>]
#
#   --kernel   Informational only — this script does NOT switch kernels.
#              Install/select the kernel with grubby and restart the VM
#              yourself first (see README "Kernel compatibility (Amazon
#              Linux 2023)"); this flag just labels the output files and is
#              asserted against `uname -r` before running.
#   --ref      git ref to archive and ship into the VM. Default: HEAD.
#              Use the v0.2.4 tag for kernel-comparison runs so results
#              describe the released code, not an in-progress worktree.
#
# Environment variables:
#   VM_NAME    Lima instance name (default: al2023-e2e)
#   OUT_DIR    where the copied-back e2e log lands (default: /tmp)
#
# What this does:
#   1. Starts (or confirms running) the al2023-e2e VM.
#   2. `git archive <ref>` the repo, `limactl copy`s the tarball in, extracts
#      it in the VM's home directory (fresh checkout each run).
#   3. Runs hack/e2e/run-e2e.sh as the Lima user (docker-group access),
#      capturing full output to a log file inside the VM.
#   4. Copies the log back to OUT_DIR.
#
# Environment note (not a product bug): this VM runs kind/docker nested
# inside QEMU on Apple Silicon. A plain `nginx:alpine` pull via the host
# docker daemon takes ~3s, but the SAME pull performed by kind's node
# containerd (the path kubelet uses) took 60-65s in testing here — just over
# run-e2e.sh's hardcoded 60s `kubectl rollout status --timeout=60s` for the
# nginx Deployment, causing a reproducible Phase 4 timeout. This script works
# around it by pre-loading nginx:alpine into the kind node with
# `kind load docker-image` right after the cluster exists (before the
# run-e2e.sh reaches Phase 4 — note this script overlays the worktree's
# run-e2e.sh, including the readiness-race fix, over the archived ${REF} (see
# step 2 below) — so the pull is a local cache hit.
# This never touches PROFILE_DIR, so it cannot desync the Phase 2 hostPath
# bind-mount (see the README note on that failure mode if you reuse a
# cluster manually across runs).
#
# This script does not stop the VM — leave it running for the next kernel,
# or `limactl stop al2023-e2e` when done.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VM_NAME="${VM_NAME:-al2023-e2e}"
OUT_DIR="${OUT_DIR:-/tmp}"
KERNEL_LABEL="unspecified"
REF="HEAD"

while [ $# -gt 0 ]; do
  case "$1" in
    --kernel) KERNEL_LABEL="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[al2023-e2e]${NC} $*"; }
warn() { echo -e "${YELLOW}[al2023-e2e]${NC} $*"; }

# ── 1. VM up ─────────────────────────────────────────────────────────────────
STATUS=$(limactl list --format json 2>/dev/null | jq -r --arg n "$VM_NAME" 'select(.name==$n) | .status')
if [ -z "$STATUS" ]; then
  info "Creating and starting ${VM_NAME}..."
  limactl start --tty=false --name="${VM_NAME}" "${SCRIPT_DIR}/../../infra/lima/al2023-e2e.yaml"
elif [ "$STATUS" != "Running" ]; then
  info "Starting ${VM_NAME} (was: ${STATUS})..."
  limactl start "${VM_NAME}"
else
  info "${VM_NAME} already running"
fi

ACTUAL_KERNEL=$(limactl shell "${VM_NAME}" -- uname -r)
info "VM kernel: ${ACTUAL_KERNEL} (label: ${KERNEL_LABEL})"
if [ "${KERNEL_LABEL}" != "unspecified" ]; then
  case "${ACTUAL_KERNEL}" in
    "${KERNEL_LABEL}".*) ;;
    *)
      warn "--kernel ${KERNEL_LABEL} does not match running kernel ${ACTUAL_KERNEL} — aborting"
      exit 1
      ;;
  esac
fi

# ── 2. Ship source in ───────────────────────────────────────────────────────
ARCHIVE="/tmp/tracepod-src-${REF//\//_}.tar.gz"
info "Archiving ${REF} -> ${ARCHIVE}"
git -C "${REPO_ROOT}" archive --format=tar.gz "${REF}" -o "${ARCHIVE}"

info "Copying archive into VM..."
limactl copy "${ARCHIVE}" "${VM_NAME}:/tmp/tracepod-src.tar.gz"

limactl shell "${VM_NAME}" -- bash -c '
  set -euo pipefail
  rm -rf ~/tracepod-src
  mkdir -p ~/tracepod-src
  tar -xzf /tmp/tracepod-src.tar.gz -C ~/tracepod-src
'

# Overlay the WORKING-TREE run-e2e.sh (with the readiness-race fix) on top of
# the archived ${REF}. `git archive` only ever contains committed content, so
# shipping just the ${REF} tarball would run the OLD, racy harness even though
# the fix lives in this worktree. Product code (everything else) stays exactly
# as released at ${REF}; only the harness script is overlaid.
info "Overlaying fixed hack/e2e/run-e2e.sh (worktree copy, not from ${REF})..."
limactl shell "${VM_NAME}" -- bash -c 'cat > ~/tracepod-src/hack/e2e/run-e2e.sh' \
  < "${REPO_ROOT}/hack/e2e/run-e2e.sh"
limactl shell "${VM_NAME}" -- bash -c 'chmod +x ~/tracepod-src/hack/e2e/run-e2e.sh'
LOCAL_SHA=$(shasum -a 256 "${REPO_ROOT}/hack/e2e/run-e2e.sh" | awk '{print $1}')
VM_SHA=$(limactl shell "${VM_NAME}" -- bash -c 'sha256sum ~/tracepod-src/hack/e2e/run-e2e.sh' | awk '{print $1}')
info "run-e2e.sh sha256 — local: ${LOCAL_SHA}  vm: ${VM_SHA}"
if [ "${LOCAL_SHA}" != "${VM_SHA}" ]; then
  warn "sha256 mismatch between local and VM copy of run-e2e.sh — aborting"
  exit 1
fi
NRI_LINE_COUNT=$(limactl shell "${VM_NAME}" -- bash -c 'grep -c "NRI connected" ~/tracepod-src/hack/e2e/run-e2e.sh')
info "Confirmed fixed harness in VM: 'NRI connected' wait present (${NRI_LINE_COUNT} match(es))"

# ── 3. Run e2e detached (the full run exceeds most tool call timeouts) ──────
RUN_ID="e2e-${KERNEL_LABEL}-$(date +%s)"
info "Starting run-e2e.sh in background as ${RUN_ID}..."
limactl shell "${VM_NAME}" -- bash -c "
  set -eu
  export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin
  cd ~/tracepod-src
  nohup bash hack/e2e/run-e2e.sh > ~/${RUN_ID}.log 2>&1 &
  echo \$! > ~/${RUN_ID}.pid
  disown
" &
LAUNCH_PID=$!
wait "$LAUNCH_PID"

# Side-load nginx:alpine into the kind node as soon as the cluster exists —
# see the environment note above. This races against the script's own Phase
# 2/3 but only needs to land before Phase 4, which is seconds away at best.
info "Waiting for the kind cluster to exist so nginx:alpine can be preloaded..."
for _ in $(seq 1 60); do
  if limactl shell "${VM_NAME}" -- bash -c "kind get clusters 2>/dev/null | grep -q '^tracepod-e2e$'"; then
    limactl shell "${VM_NAME}" -- bash -c \
      "docker pull -q nginx:alpine >/dev/null 2>&1; kind load docker-image nginx:alpine --name tracepod-e2e" \
      || warn "nginx:alpine preload failed — Phase 4 may hit the slow-pull timeout"
    break
  fi
  sleep 3
done

info "Waiting for ${RUN_ID} to finish (this can take 10-20+ minutes)..."
until ! limactl shell "${VM_NAME}" -- bash -c "kill -0 \$(cat ~/${RUN_ID}.pid) 2>/dev/null"; do
  sleep 15
done

# ── 4. Copy results back ─────────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
limactl copy "${VM_NAME}:${RUN_ID}.log" "${OUT_DIR}/${RUN_ID}.log" 2>/dev/null || \
  warn "could not copy log back yet — it may still be running; check with: limactl shell ${VM_NAME} -- tail -f ~/${RUN_ID}.log"
# run-e2e.sh has no separate exit-code file; its own trap prints a distinct
# PASS banner on success and "[e2e FAIL]" on any failure, so grep the log.
info "Log: ${OUT_DIR}/${RUN_ID}.log"
if grep -q "PASS: tracepod e2e test complete" "${OUT_DIR}/${RUN_ID}.log" 2>/dev/null; then
  info "PASS (kernel label: ${KERNEL_LABEL}, uname -r: ${ACTUAL_KERNEL})"
else
  warn "FAIL or incomplete (kernel label: ${KERNEL_LABEL}, uname -r: ${ACTUAL_KERNEL}) — see ${OUT_DIR}/${RUN_ID}.log"
fi

exit 0
