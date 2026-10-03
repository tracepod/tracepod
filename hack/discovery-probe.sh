#!/usr/bin/env bash
# discovery-probe.sh — check whether a node can support Tracepod's sensor.
#
# The sensor discovers containers via containerd's NRI. NRI ships disabled by
# default below containerd 2.0; managed node pools on containerd 2.x images
# (current EKS AL2023, AKS Ubuntu 24.04, AKS Azure Linux 3.0) have it on by
# default, while older images (e.g. AKS Ubuntu 22.04, containerd 1.7) still
# ship it off. On a node where it's off, the sensor now refuses to run (exits
# non-zero, CrashLoopBackOffs) rather than tracing nothing silently — see
# docs/KNOWN-LIMITATIONS.md §0.6. This script turns that into an answer you
# get BEFORE deploying.
#
# It also measures the preconditions a future cgroupfs-based fallback would
# need, so the viability question on hardened node OSes (Bottlerocket, SELinux)
# can be settled with data rather than assumption.
#
# Usage:
#   ./hack/discovery-probe.sh                        # run directly on a node
#
#   # Or via a node-debug pod (no SSH access to the node required). The debug
#   # pod's own /sys and /proc reflect ONLY the container, not the host — the
#   # host filesystem is bind-mounted at /host instead — so HOST_ROOT must be
#   # set, and the image needs bash + socat (not just /bin/sh):
#   kubectl debug node/<name> -it --image=ubuntu:24.04 -- bash
#   # inside the debug pod:
#   apt-get update -qq && apt-get install -y -qq curl socat
#   curl -fsSLO https://raw.githubusercontent.com/tracepod/tracepod/v0.2.4/hack/discovery-probe.sh
#   HOST_ROOT=/host bash discovery-probe.sh
#
# Environment variables:
#   HOST_ROOT          prefix for CGROUP_ROOT/NRI_SOCKET/CONTAINERD_CONFIG
#                      defaults (default: "", i.e. run directly on the node).
#                      Set to /host when run from a node-debug pod. The BTF
#                      check always reads the container's own /sys — BTF is
#                      global kernel state, not namespaced, so it needs no
#                      prefix even under HOST_ROOT.
#   CGROUP_ROOT        override the full path (default: $HOST_ROOT/sys/fs/cgroup)
#   NRI_SOCKET         override the full path (default: $HOST_ROOT/run/nri/nri.sock —
#                      /run, not /var/run: /var/run is itself a symlink to /run on
#                      Debian/Ubuntu-family nodes (including kind's), and an absolute
#                      symlink target escapes the $HOST_ROOT prefix on resolution, so
#                      $HOST_ROOT/var/run/... silently resolves to the DEBUG POD's own
#                      /run instead of the host's — confirmed against a live kind node)
#   CONTAINERD_CONFIG  override the full path (default: $HOST_ROOT/etc/containerd/config.toml)
#
# Exit codes:
#   0  NRI reachable — the sensor will work
#   1  NRI unreachable — the sensor would trace nothing (see remediation output)
#   2  probe could not run (missing tooling, not Linux)
#
# Read-only: this script never writes outside /tmp and never restarts anything.

set -uo pipefail

HOST_ROOT="${HOST_ROOT:-}"
CGROUP_ROOT="${CGROUP_ROOT:-${HOST_ROOT}/sys/fs/cgroup}"
NRI_SOCKET="${NRI_SOCKET:-${HOST_ROOT}/run/nri/nri.sock}"
CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-${HOST_ROOT}/etc/containerd/config.toml}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[1m'; N=$'\033[0m'
else
  G=''; Y=''; R=''; B=''; N=''
fi

pass() { printf '%s  PASS%s  %s\n' "$G" "$N" "$*"; }
warn() { printf '%s  WARN%s  %s\n' "$Y" "$N" "$*"; }
fail() { printf '%s  FAIL%s  %s\n' "$R" "$N" "$*"; }
info() { printf '        %s\n' "$*"; }
head2() { printf '\n%s%s%s\n' "$B" "$*" "$N"; }

[ "$(uname -s)" = "Linux" ] || { fail "not Linux (uname -s = $(uname -s))"; exit 2; }

printf '%sTracepod discovery probe%s\n' "$B" "$N"
info "kernel  $(uname -r)"
info "host    $(hostname 2>/dev/null || echo unknown)"

# ── 1. NRI: the only discovery mechanism the sensor actually has ──────────────
head2 "1. containerd NRI (required)"

NRI_OK=1
if [ -S "$NRI_SOCKET" ]; then
  pass "NRI socket present: $NRI_SOCKET"
  # Presence is necessary but not sufficient — the plugin can be disabled while
  # the path still exists. Probe a connect when a tool is available.
  if command -v socat >/dev/null 2>&1; then
    if timeout 2 socat -u OPEN:/dev/null "UNIX-CONNECT:$NRI_SOCKET" 2>/dev/null; then
      pass "NRI socket accepts connections"
      NRI_OK=0
    else
      fail "NRI socket exists but refuses connections — plugin likely disabled"
    fi
  else
    warn "socat not present — cannot verify the socket accepts connections"
    info "socket exists, so NRI is probably enabled; confirm in $CONTAINERD_CONFIG"
    NRI_OK=0
  fi
else
  fail "NRI socket absent: $NRI_SOCKET"
fi

if [ -r "$CONTAINERD_CONFIG" ]; then
  if grep -qE '\[plugins\."io\.containerd\.nri\.v1\.nri"\]' "$CONTAINERD_CONFIG" 2>/dev/null; then
    DISABLED=$(awk '/\[plugins\."io\.containerd\.nri\.v1\.nri"\]/{f=1;next} /^\[/{f=0} f && /disable/{print;exit}' \
      "$CONTAINERD_CONFIG" 2>/dev/null | tr -d ' ')
    case "$DISABLED" in
      *"=true"*)
        # Authoritative: overrides a socket check that passed on a stale or
        # leftover socket path. Config wins over inode presence.
        fail "containerd config sets NRI disable = true"
        NRI_OK=1
        ;;
      *"=false"*) pass "containerd config sets NRI disable = false" ;;
      *)          warn "NRI section present but no explicit 'disable' setting" ;;
    esac
  else
    warn "no NRI section in $CONTAINERD_CONFIG (defaults apply: disabled below containerd 2.0)"
  fi
else
  info "containerd config not readable at $CONTAINERD_CONFIG — skipping config check"
fi

# ── 2. BTF: required for CO-RE ────────────────────────────────────────────────
head2 "2. Kernel BTF (required)"
if [ -r /sys/kernel/btf/vmlinux ]; then
  pass "/sys/kernel/btf/vmlinux readable"
else
  fail "/sys/kernel/btf/vmlinux missing or unreadable — the sensor cannot load its BPF programs"
  info "the DaemonSet mounts this path with type: Directory, so the pod will hang in ContainerCreating"
fi

# ── 3. cgroup v2 ──────────────────────────────────────────────────────────────
# The sensor identifies cgroups by directory inode (bpf_get_current_cgroup_id).
# Those semantics are cgroup v2 only; on v1 the inodes it would collect are
# never what the kernel reports, so it would allowlist meaningless IDs.
head2 "3. cgroup v2 (required)"
CGROUP_V2=1
if command -v stat >/dev/null 2>&1; then
  FSTYPE=$(stat -f -c %T "$CGROUP_ROOT" 2>/dev/null || echo unknown)
  if [ "$FSTYPE" = "cgroup2fs" ]; then
    pass "$CGROUP_ROOT is cgroup2fs"
    CGROUP_V2=0
  else
    fail "$CGROUP_ROOT is '$FSTYPE', not cgroup2fs — cgroup v1 is unsupported"
  fi
else
  warn "stat(1) unavailable — cannot determine cgroup version"
fi

# ── 4. cgroupfs readability (fallback precondition) ───────────────────────────
# The sensor never writes here: it stats directories and reads cgroup.procs.
# A read-only mount is sufficient and is what the DaemonSet requests.
head2 "4. cgroupfs access (read-only is sufficient)"
if [ -r "$CGROUP_ROOT" ]; then
  pass "$CGROUP_ROOT readable"
else
  fail "$CGROUP_ROOT not readable"
fi

KUBEPODS=$(find "$CGROUP_ROOT" -maxdepth 3 -type d -name '*kubepods*' 2>/dev/null | head -1)
if [ -n "$KUBEPODS" ]; then
  pass "kubepods tree found: $KUBEPODS"
  case "$KUBEPODS" in
    *.slice) info "cgroup driver: systemd" ;;
    *)       info "cgroup driver: cgroupfs" ;;
  esac
  SCOPE=$(find "$KUBEPODS" -maxdepth 3 -type d \( -name '*.scope' -o -name 'cri-containerd-*' \) 2>/dev/null | head -1)
  if [ -n "$SCOPE" ]; then
    [ -r "$SCOPE/cgroup.procs" ] && pass "cgroup.procs readable" || fail "cgroup.procs not readable"
    if [ -r "$SCOPE/cgroup.events" ]; then
      pass "cgroup.events readable ($(tr '\n' ' ' < "$SCOPE/cgroup.events" 2>/dev/null))"
    else
      warn "cgroup.events not readable — a future fallback would lose its stop signal"
    fi
  else
    info "no container scope found to sample (no running pods?)"
  fi
else
  warn "no kubepods tree under $CGROUP_ROOT — is the kubelet running on this node?"
fi

# ── 5. inotify (fallback precondition) ────────────────────────────────────────
head2 "5. inotify on cgroupfs (fallback precondition only)"
if [ -r /proc/sys/fs/inotify/max_user_watches ]; then
  info "max_user_watches = $(cat /proc/sys/fs/inotify/max_user_watches) (shared per UID, node-wide)"
fi
if command -v inotifywait >/dev/null 2>&1 && [ -n "${KUBEPODS:-}" ]; then
  if timeout 1 inotifywait -q -t 1 -e create "$KUBEPODS" >/dev/null 2>&1 || [ $? -eq 2 ]; then
    pass "inotify watch can be installed on the kubepods tree"
  else
    warn "could not install an inotify watch — SELinux or LSM policy may forbid it"
  fi
else
  info "inotifywait not present — skipping (informational only; not needed for NRI)"
fi

# ── Verdict ───────────────────────────────────────────────────────────────────
head2 "Verdict"
if [ "$NRI_OK" -eq 0 ] && [ "$CGROUP_V2" -eq 0 ]; then
  pass "This node can run the Tracepod sensor."
  exit 0
fi

fail "The sensor would NOT profile anything on this node."
echo
if [ "$NRI_OK" -ne 0 ]; then
  info "Enable NRI in containerd (${CONTAINERD_CONFIG}):"
  echo
  info '  [plugins."io.containerd.nri.v1.nri"]'
  info '    disable = false'
  info '    socket_path = "/var/run/nri/nri.sock"'
  echo
  info "then restart containerd. On EKS use a custom launch template's bootstrap"
  info "userdata; on AKS use node customization. containerd >= 2.0 enables NRI by"
  info "default. See docs/KNOWN-LIMITATIONS.md §0.6."
fi
[ "$CGROUP_V2" -ne 0 ] && info "cgroup v2 is required and cannot be worked around on this node."
exit 1
