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
# Since v0.2.2, `--cgroup-path` registers a userspace aggregator before
# allowlisting the cgroup (see cmd/sensor/main.go registerManualCgroup), so
# step 7 below is a real end-to-end check: a manual cgroup's opens/execs must
# show up in the sensor's verbose output, not merely load and attach.
#
# A true end-to-end run would need containerd + NRI configured in the VM so
# a real container start goes through onContainerStart; that roughly doubles
# the setup here and contradicts the expected (and fine) "NRI unreachable"
# result from discovery-probe.sh in this bare rig. Left as a follow-up.
#
# Exit code: 0 if every check PASSes, 1 if any check FAILs.
set -uo pipefail

SENSOR_VERSION="0.2.3"
RELEASE_BASE="https://github.com/tracepod/tracepod/releases/download/v${SENSOR_VERSION}"
WORKDIR="$(mktemp -d /tmp/tp-kernel-compat.XXXXXX)"
CGROUP="/sys/fs/cgroup/tp-compat"
SENTINEL_DIR="/var/lib/tp-compat"
FAILED=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILED=1; }
warn() { printf '  WARN  %s\n' "$*"; }
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

case "$(uname -m)" in
  aarch64|arm64) HOST_ARCH="arm64" ;;
  x86_64|amd64) HOST_ARCH="amd64" ;;
  *) fail "unsupported architecture '$(uname -m)' — no released sensor tarball for it"; exit 1 ;;
esac
info "detected arch: $(uname -m) -> $HOST_ARCH"
SENSOR_TARBALL="tracepod_sensor_${SENSOR_VERSION}_linux_${HOST_ARCH}.tar.gz"

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

  head2 "6. Sensor BPF programs execute (system-wide run_cnt) ($mode)"
  # run_cnt counts executions system-wide — the kprobe itself filters by
  # cgroup internally — so a nonzero count proves the program runs on this
  # kernel, not that events for the test cgroup specifically reached
  # userspace (that is step 7's job).
  sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1
  local stats_rc=$?
  local sentinel="$SENTINEL_DIR/sentinel-$mode-$$"
  local exe="$SENTINEL_DIR/tp-exec-$mode-$$"
  echo "tracepod-kernel-compat-$mode-$RANDOM" > "$sentinel"
  cp /usr/bin/true "$exe"; chmod +x "$exe"

  bash -c "echo \$\$ > $CGROUP/cgroup.procs; cat $sentinel >/dev/null; $exe"
  sleep 1

  local required_progs="kprobe_openat kprobe_execve kprobe_mmap"
  if [ "$mode" = "trace-stat" ]; then required_progs="$required_progs kprobe_stat"; fi

  if ! command -v bpftool >/dev/null 2>&1; then
    warn "[$mode] bpftool not available — cannot confirm sensor programs executed"
  else
    if [ "$stats_rc" -ne 0 ]; then
      warn "[$mode] 'sysctl -w kernel.bpf_stats_enabled=1' failed — run_cnt below may read as 0 regardless of whether the program actually ran"
    fi

    local bpftool_out
    bpftool_out="$(bpftool prog show 2>/dev/null)"

    local -A prog_runcnt=()
    while read -r pname pcount; do
      [ -n "$pname" ] && prog_runcnt["$pname"]="$pcount"
    done < <(printf '%s\n' "$bpftool_out" | awk '
      function flush(b) {
        name = ""; runcnt = ""
        n = split(b, arr, " ")
        for (i = 1; i <= n; i++) {
          if (arr[i] == "name") name = arr[i + 1]
          if (arr[i] == "run_cnt") runcnt = arr[i + 1]
        }
        if (name != "") print name, (runcnt == "" ? "NA" : runcnt)
      }
      /^[0-9]+:/ { if (block != "") flush(block); block = $0; next }
      { block = block " " $0 }
      END { if (block != "") flush(block) }
    ')

    for prog in $required_progs; do
      if [ -n "${prog_runcnt[$prog]+x}" ]; then
        info "[$mode] bpftool: $prog run_cnt=${prog_runcnt[$prog]}"
      else
        fail "[$mode] sensor program '$prog' not found in 'bpftool prog show' output"
      fi
    done
    # kprobe_stat may be loaded even in plain "openat" mode (bpf2go loads the
    # full program set); it is not required there, so only report it.
    if [ "$mode" = "openat" ] && [ -n "${prog_runcnt[kprobe_stat]+x}" ]; then
      info "[$mode] bpftool: kprobe_stat run_cnt=${prog_runcnt[kprobe_stat]} (loaded but not required in this mode)"
    fi

    if [ -n "${prog_runcnt[kprobe_openat]+x}" ]; then
      local openat_runcnt="${prog_runcnt[kprobe_openat]}"
      if [ "$openat_runcnt" != "NA" ] && [ "$openat_runcnt" -gt 0 ] 2>/dev/null; then
        pass "[$mode] kprobe_openat run_cnt=$openat_runcnt (nonzero — sensor's BPF program executed on this kernel)"
      else
        fail "[$mode] kprobe_openat run_cnt is zero or unreadable ($openat_runcnt) — program did not execute"
      fi
    fi
  fi

  head2 "7. Userspace recording through --cgroup-path ($mode)"
  if grep -qE "file=$sentinel|exec=$exe" "$logf"; then
    pass "[$mode] sensor verbose log recorded the sentinel (aggregator existed for this cgroup)"
  else
    fail "[$mode] sensor verbose log has no 'file=' or 'exec=' line for the sentinel/exec — --cgroup-path recording regressed (see cmd/sensor/main.go registerManualCgroup)"
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
  echo "ALL CHECKS PASSED"
else
  echo "AT LEAST ONE CHECK FAILED"
fi
exit "$FAILED"
