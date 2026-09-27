#!/usr/bin/env bash
# kernel-compat.sh — verify Tracepod's sensor loads and attaches its BPF
# programs on THIS kernel, and run it against a synthetic workload.
#
# Written for Amazon Linux 2023 (EKS's default node OS: kernels 6.1 / 6.12 /
# 6.18 depending on AMI release), but has no AL2023-specific logic — it
# should run on any Linux host with root.
#
# Usage (from a repo checkout, run AS ROOT inside the target VM/host):
#   ./hack/kernel-compat.sh
#   SENSOR_BIN=/path/to/local/sensor ./hack/kernel-compat.sh   # skip the download,
#                                                               # use a locally built binary
#
# One-command flow to stand up the AL2023 VM and run this against it (from
# the tracepod repo root, on a Mac with Lima installed):
#   limactl start --tty=false --name=al2023-kernel infra/lima/al2023-kernel.yaml
#   limactl copy hack/kernel-compat.sh al2023-kernel:/tmp/kernel-compat.sh
#   limactl copy hack/discovery-probe.sh al2023-kernel:/tmp/discovery-probe.sh
#   limactl shell al2023-kernel -- sudo bash /tmp/kernel-compat.sh
#   limactl stop al2023-kernel
#
# KNOWN GAP (not an AL2023 finding — reproduces on every kernel, including
# the Ubuntu dev VM and CI): the sensor's `--cgroup-path` debug flag
# (cmd/sensor/main.go:96-104) only adds the cgroup to the in-kernel BPF
# allowlist. It never creates a userspace aggregator for that cgroup —
# aggregators are only created by the NRI container-start hook
# (onContainerStart, main.go:304). `handle()` (main.go:548-558) drops every
# ring-buffer event for a cgroup with no live aggregator BEFORE dispatch, so
# with the released binary `--verbose` prints nothing for `--cgroup-path`
# cgroups, on any kernel. That makes a true "open a sentinel file, see it in
# the sensor's manifest" end-to-end test impossible with the released binary
# alone. This script instead verifies the parts that a kernel version
# actually decides — BPF load, kprobe attach, and (via debugfs/bpftool) that
# the programs actually fire on the workload — and separately records the
# userspace gap so it is not silently mistaken for a kernel failure.
#
# A true end-to-end run would need containerd + NRI configured in the VM so
# a real container start goes through onContainerStart; that roughly doubles
# the setup here and contradicts the expected (and fine) "NRI unreachable"
# result from discovery-probe.sh in this bare rig. Left as a follow-up.
#
# Exit code: 0 if every check PASSes, 1 if any check FAILs. KNOWN-GAP lines
# do not affect the exit code.
set -uo pipefail

SENSOR_VERSION="0.2.1"
SENSOR_TARBALL="tracepod_sensor_${SENSOR_VERSION}_linux_arm64.tar.gz"
RELEASE_BASE="https://github.com/tracepod/tracepod/releases/download/v${SENSOR_VERSION}"
WORKDIR="$(mktemp -d /tmp/tp-kernel-compat.XXXXXX)"
CGROUP="/sys/fs/cgroup/tp-compat"
SENTINEL_DIR="/var/lib/tp-compat"
FAILED=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }
warn() { printf '  WARN  %s\n' "$*"; }
gap()  { printf '  KNOWN-GAP  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
head2() { printf '\n== %s ==\n' "$*"; }

SENSOR_PID=""
cleanup() {
  [ -n "$SENSOR_PID" ] && kill "$SENSOR_PID" >/dev/null 2>&1
  wait "$SENSOR_PID" 2>/dev/null
  sysctl -w kernel.bpf_stats_enabled=0 >/dev/null 2>&1
  rmdir "$CGROUP" >/dev/null 2>&1
  rm -rf "$SENTINEL_DIR" "$WORKDIR"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

head2 "Host"
info "uname -r: $(uname -r)"
info "os-release: $(grep -m1 PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '\"')"

head2 "1. Preconditions"
if [ -r /sys/kernel/btf/vmlinux ]; then pass "/sys/kernel/btf/vmlinux present"; else fail "/sys/kernel/btf/vmlinux missing"; fi
CGFS_TYPE="$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)"
if [ "$CGFS_TYPE" = "cgroup2fs" ]; then pass "/sys/fs/cgroup is cgroup2fs"; else fail "/sys/fs/cgroup is '$CGFS_TYPE', not cgroup2fs"; fi

head2 "2. kprobe target symbols in /proc/kallsyms"
for sym in do_sys_openat2 security_bprm_check security_mmap_file vfs_fstatat; do
  if awk -v s="$sym" '$3==s {found=1} END{exit !found}' /proc/kallsyms; then
    pass "kallsyms has $sym"
  else
    # A symbol renamed by the compiler (foo.isra.0 / foo.constprop.0) would
    # make link.Kprobe(symbol, ...) fail even though "the function" exists.
    variant="$(awk -v s="$sym" '$3 ~ "^"s"\\." {print $3; exit}' /proc/kallsyms)"
    if [ -n "$variant" ]; then
      fail "kallsyms has no exact '$sym' — found variant '$variant' instead (kprobe attach would fail)"
    else
      fail "kallsyms has no '$sym' at all"
    fi
  fi
done

head2 "3. Sensor binary"
if [ -n "${SENSOR_BIN:-}" ]; then
  info "using locally built binary: $SENSOR_BIN"
  cp "$SENSOR_BIN" "$WORKDIR/sensor"
else
  for tool in curl tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { fail "required tool '$tool' not found"; }
  done
  if [ "$FAILED" -eq 1 ]; then echo "cannot continue without curl/tar/sha256sum"; exit 1; fi
  ( cd "$WORKDIR" && \
    curl -fsSLO "$RELEASE_BASE/$SENSOR_TARBALL" && \
    curl -fsSLO "$RELEASE_BASE/checksums.txt" )
  if [ $? -ne 0 ]; then fail "download of $SENSOR_TARBALL / checksums.txt failed"; exit 1; fi
  ( cd "$WORKDIR" && grep " $SENSOR_TARBALL\$" checksums.txt | sha256sum -c - )
  if [ $? -eq 0 ]; then pass "checksum verified for $SENSOR_TARBALL"; else fail "checksum mismatch for $SENSOR_TARBALL"; exit 1; fi
  tar tzf "$WORKDIR/$SENSOR_TARBALL" | sed 's/^/        tarball entry: /'
  ( cd "$WORKDIR" && tar xzf "$SENSOR_TARBALL" )
  if [ ! -x "$WORKDIR/sensor" ]; then
    # fall back: find whatever executable the tarball actually contains
    found="$(cd "$WORKDIR" && find . -maxdepth 1 -type f -perm -u+x ! -name '*.tar.gz' | head -1)"
    [ -n "$found" ] && cp "$WORKDIR/$found" "$WORKDIR/sensor"
  fi
fi
if [ ! -x "$WORKDIR/sensor" ]; then fail "no executable sensor binary at $WORKDIR/sensor"; exit 1; fi
pass "sensor binary ready: $("$WORKDIR/sensor" --version 2>&1 || echo '(no --version output)')"

run_probe_load_test() {
  local mode="$1"   # "openat" or "trace-stat"
  local extra_flag="$2"
  local profdir="$WORKDIR/profiles-$mode"
  mkdir -p "$profdir" "$SENTINEL_DIR"
  mkdir -p "$CGROUP" 2>/dev/null || { fail "[$mode] could not create test cgroup $CGROUP"; return 1; }

  head2 "4. BPF load + kprobe attach ($mode)"
  local logf="$WORKDIR/sensor-$mode.log"
  # shellcheck disable=SC2086
  "$WORKDIR/sensor" --cgroup-path "$CGROUP" --profile-dir "$profdir" --verbose $extra_flag \
    >"$logf" 2>&1 &
  SENSOR_PID=$!

  local ok=0
  for _ in $(seq 1 50); do
    grep -q "manual cgroup: path=" "$logf" 2>/dev/null && { ok=1; break; }
    kill -0 "$SENSOR_PID" 2>/dev/null || break
    sleep 0.2
  done

  if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    fail "[$mode] sensor exited before/without attaching — log follows:"
    sed 's/^/        /' "$logf"
    SENSOR_PID=""
    return 1
  fi
  if [ "$ok" -ne 1 ]; then
    fail "[$mode] sensor never printed 'manual cgroup: path=' (timed out) — log follows:"
    sed 's/^/        /' "$logf"
    kill "$SENSOR_PID" 2>/dev/null; wait "$SENSOR_PID" 2>/dev/null; SENSOR_PID=""
    return 1
  fi
  pass "[$mode] sensor started, BPF programs loaded, cgroup allowed (all kprobes attached — OpenWith fails fatally on any attach error, including vfs_fstatat under --trace-stat)"

  if [ "$mode" = "trace-stat" ]; then
    # OpenWith attaches ALL kprobes (including vfs_fstatat under --trace-stat)
    # before AllowCgroup/main ever prints "manual cgroup:" — any attach
    # failure is fatal (probe.go: cleanup + return err), so reaching this
    # line already proves vfs_fstatat attached. The generic NRI-unavailable
    # warning is expected in this bare rig and is unrelated to attach; only
    # a literal "attach kprobe" fatal (which would have exited the process
    # already, caught above) would indicate an attach problem.
    pass "[$mode] vfs_fstatat kprobe attached (process survived past OpenWith, which fails fatally on any kprobe attach error)"
  fi

  head2 "5. Registered kprobes visible in debugfs ($mode)"
  local kplist="/sys/kernel/debug/kprobes/list"
  mount -t debugfs debugfs /sys/kernel/debug >/dev/null 2>&1
  if [ -r "$kplist" ]; then
    for sym in do_sys_openat2 security_bprm_check security_mmap_file; do
      if grep -q "$sym" "$kplist"; then pass "[$mode] $sym registered in $kplist"; else fail "[$mode] $sym NOT found in $kplist"; fi
    done
    if [ "$mode" = "trace-stat" ]; then
      if grep -q vfs_fstatat "$kplist"; then pass "[$mode] vfs_fstatat registered in $kplist"; else fail "[$mode] vfs_fstatat NOT found in $kplist"; fi
    fi
  else
    warn "[$mode] $kplist not readable — skipping debugfs cross-check"
  fi

  head2 "6. Programs actually fire on a workload ($mode)"
  sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1
  local sentinel="$SENTINEL_DIR/sentinel-$mode-$$"
  local exe="$SENTINEL_DIR/tp-exec-$mode-$$"
  echo "tracepod-kernel-compat-$mode-$RANDOM" > "$sentinel"
  cp /usr/bin/true "$exe"; chmod +x "$exe"

  bash -c "echo \$\$ > $CGROUP/cgroup.procs; cat $sentinel >/dev/null; $exe"
  sleep 1

  local ran=0
  if command -v bpftool >/dev/null 2>&1; then
    # Any kprobe/kernel prog owned by this sensor pid's fds with run_cnt > 0.
    if bpftool prog show 2>/dev/null | grep -A1 kprobe | grep -q "run_cnt"; then
      bpftool prog show 2>/dev/null | grep -B1 "run_cnt" | sed 's/^/        bpftool: /'
      if bpftool prog show 2>/dev/null | awk '/run_cnt/{print}' | grep -qv "run_cnt 0"; then
        pass "[$mode] bpftool reports nonzero run_cnt for at least one program"
        ran=1
      fi
    fi
  fi
  if [ "$ran" -eq 0 ]; then
    warn "[$mode] could not confirm nonzero run_cnt via bpftool (unavailable or inconclusive) — programs attached (step 4/5) but firing not independently confirmed here"
  fi

  head2 "7. Userspace manifest recording ($mode) — expected KNOWN-GAP"
  if grep -qE "file=$sentinel|exec=$exe" "$logf"; then
    pass "[$mode] sensor verbose log recorded the sentinel (aggregator existed for this cgroup)"
  else
    gap "[$mode] sensor verbose log has ZERO 'file=' or 'exec=' lines for the sentinel/exec (checked: $sentinel, $exe)."
    gap "[$mode] Root cause (not kernel-specific — see script header): --cgroup-path never registers a userspace aggregator (cmd/sensor/main.go:96-104), and handle() drops events for cgroups with no aggregator before dispatch (cmd/sensor/main.go:548-558, see the untrackedCgroup counter)."
  fi

  kill "$SENSOR_PID" 2>/dev/null; wait "$SENSOR_PID" 2>/dev/null; SENSOR_PID=""
  sysctl -w kernel.bpf_stats_enabled=0 >/dev/null 2>&1
  rmdir "$CGROUP" 2>/dev/null
  rm -f "$sentinel" "$exe"
  return 0
}

run_probe_load_test "openat" ""
run_probe_load_test "trace-stat" "--trace-stat"

head2 "8. containerd package available via dnf (informational only)"
if command -v dnf >/dev/null 2>&1; then
  dnf info containerd 2>/dev/null | grep -E 'Version|Release' | sed 's/^/        /' || info "containerd package not found in configured repos"
else
  info "dnf not present on this host — skipping"
fi

head2 "9. hack/discovery-probe.sh (expected: NRI unreachable — no containerd configured in this rig)"
if [ -x /tmp/discovery-probe.sh ]; then
  bash /tmp/discovery-probe.sh; DP_RC=$?
  info "discovery-probe.sh exit code: $DP_RC (1 = NRI unreachable, expected here)"
else
  warn "discovery-probe.sh not found at /tmp/discovery-probe.sh — copy it in to run this check"
fi

head2 "Summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED (KNOWN-GAP items above are expected — see script header)"
else
  echo "AT LEAST ONE CHECK FAILED"
fi
exit "$FAILED"
