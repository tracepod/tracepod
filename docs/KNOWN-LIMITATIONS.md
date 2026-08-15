# Known Limitations

Honest assessment of what the Tracepod sensor cannot observe and why.
Each limitation includes: technical root cause, risk level, current workaround,
and long-term fix direction.

---

## 0. Sensor requires `privileged` and `hostPID`

### What happens

The sensor attaches BPF kprobes to kernel functions and reads cgroup IDs to
identify which container each event belongs to. These operations require elevated
privileges and host PID namespace access. Running the sensor container without
`privileged: true` and `hostPID: true` causes either silent failure (kprobe
attachment silently rejected) or an explicit error at startup.

### Risk level

**Deployment blocker in hardened environments.**

Most standard Linux hosts and self-hosted Kubernetes nodes allow privileged
DaemonSet pods. Environments that block this:

- **GKE Autopilot** — blocks privileged pods at the admission controller level
- **AWS Fargate** — no access to the underlying node; DaemonSets are not supported
- **OpenShift** — requires a custom SecurityContextConstraint (SCC) for privileged access
- **Hardened CI runners** with restricted seccomp profiles

### Current workaround

Use the Helm chart which sets these fields automatically. For manual deployment,
ensure the DaemonSet spec includes:

```yaml
spec:
  hostPID: true
  containers:
  - name: sensor
    securityContext:
      privileged: true
```

### Long-term direction

Fine-grained Linux capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`) can
replace `--privileged` on kernels ≥ 5.8. This requires auditing every capability
used by the kprobe attachment path.

---

## 0.5. Sensor only profiles CRI-managed containers

### What happens

The sensor connects to containerd via NRI (Node Resource Interface). NRI events
(`CreateContainer`, `StartContainer`, `StopContainer`) are only fired for containers
launched through the **CRI plugin** — i.e., via `kubelet` or `crictl`. Containers
started with `docker run`, `nerdctl run`, or `ctr run` use the native containerd API
directly and do not trigger NRI events.

The result is a **silent miss**: the sensor appears healthy (`NRI connected — waiting
for containers.`), the container runs normally, and no manifest is written. There is no
error message from either the sensor or the container.

### Risk level

**High usability impact — the most likely initial user error.**

A user who starts a target container with `docker run` and then calls `harden build`
will find no manifest in `profiles/` and no obvious explanation why.

### Current workaround

Always start the profiling target via `crictl` or through Kubernetes:

```bash
# Using crictl directly:
cat > /tmp/pod.json <<'EOF'
{"metadata":{"name":"target-pod","namespace":"default","uid":"target001"},"log_directory":"/tmp","linux":{}}
EOF
cat > /tmp/ctr.json <<'EOF'
{"metadata":{"name":"target"},"image":{"image":"nginx:1.25-alpine"},"log_path":"target.log","linux":{}}
EOF

sudo crictl pull nginx:1.25-alpine
POD=$(sudo crictl runp /tmp/pod.json)
CTR=$(sudo crictl create $POD /tmp/ctr.json /tmp/pod.json)
sudo crictl start $CTR
```

Or deploy as a Kubernetes workload — kubelet uses the CRI and all pods are profiled
automatically when the sensor is running.

### Long-term direction

Subscribe to containerd's event stream directly (not via NRI) as a secondary path,
so that non-CRI containers (`docker run`, `nerdctl run`) can also be profiled.

---

## 0.6. NRI is disabled by default on managed Kubernetes

### What happens

The sensor's only container-discovery mechanism is containerd's NRI. **NRI ships
disabled by default in containerd below 2.0**, and managed node pools (EKS, AKS)
generally do not enable it.

On such a node the sensor starts, fails to connect, prints one line to stderr,
and keeps running:

```
warn: NRI unavailable (start NRI stub: failed to connect to NRI service:
dial unix /var/run/nri/nri.sock: connect: connection refused) — no containers will be traced
```

The pod stays `READY=true` with zero restarts. The BPF allowlist stays empty, so
no events are emitted and no profiles are ever produced.

### Risk level

**High, and the danger is the silence rather than the outage.** In a controller
deployment the dashboard does not go blank — it keeps serving the profiling
sessions it already had, so the system reads as healthy while observing nothing.

Reproduced on 2026-08-15 by setting `disable = true` under
`[plugins."io.containerd.nri.v1.nri"]` on a kind node: the sensor pod stayed
Ready, `/api/v1/health` returned 200, the dashboard summary was byte-identical
to its pre-break state, and a freshly deployed workload never appeared.

### How to check

```sh
hack/discovery-probe.sh
```

Run it on a node (or as a privileged pod) before deploying. It reports whether
NRI is reachable and whether the cgroup filesystem preconditions hold, and exits
non-zero when the sensor would trace nothing.

### Current workaround

**Enable NRI in containerd.** On any node where you control the containerd
config, add:

```toml
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  socket_path = "/var/run/nri/nri.sock"
```

then restart containerd. Where to put it:

| Platform | Mechanism |
|---|---|
| EKS (managed node group with a **custom launch template**) | bootstrap userdata writes the config and restarts containerd before the kubelet starts |
| EKS (self-managed nodes / karpenter `NodeClass`) | same, via the AMI's userdata or a `NodeClass` userdata block |
| AKS | node customization / custom node configuration on the node pool |
| kubeadm, k3s, on-prem | edit `/etc/containerd/config.toml` directly |
| containerd ≥ 2.0 | NRI is enabled by default — nothing to do |

This is the recommended fix wherever it is available: it costs one bootstrap
line and gives the sensor its strongest discovery signal (see §1 — the NRI
`StartContainer` hook is a synchronous barrier, so the sensor attaches *before*
the workload execs).

### Where this does not work

Managed node groups with no custom launch template, and hardened node OSes such
as Bottlerocket, where containerd's configuration is not operator-editable. On
those nodes Tracepod cannot currently profile workloads. That is a documented
non-support, not a silent degradation — the probe script above tells you so
before you deploy.

### Long-term direction

A cgroupfs-based discovery fallback that does not depend on NRI. Designed but
deliberately **not implemented**: the design has been through three adversarial
review rounds and each round found defects whose failure mode was a *falsely
clean* profile — fewer observed files, read as cleaner rather than broken. Since
a truncated profile can produce a minimised image that is missing files, an
honest "not supported here" is preferable to a fallback that might quietly
under-report. Revisit once the target environments can actually be tested.

---

## 1. NRI startup race

### What happens

The NRI `StartContainer` hook fires _after_ the container's init process has already exec'd.
The application's master process opens files during its own startup sequence — pid file,
log directories, cache directories, config files opened before the first worker fork — before
the cgroup ID is registered in the eBPF allowlist. Those `openat` events are discarded
in-kernel and never reach the ring buffer or the manifest.

Timeline for nginx:

```
containerd: container init exec'd
  → /bin/sh exec'd (entrypoint interpreter)
  → /docker-entrypoint.sh executed
  → /docker-entrypoint.d/*.sh scripts executed
      (opens /bin/grep, /bin/sed, /bin/touch, /bin/find, etc.)
  → nginx master opens /run/nginx.pid
  → nginx master opens /var/log/nginx/access.log, /var/log/nginx/error.log
  → nginx master creates /var/cache/nginx/{client,proxy,fastcgi,uwsgi,scgi}_temp/
  → NRI StartContainer callback fires  ←── cgroup registered here
  → sensor begins recording events
```

Everything opened before the `StartContainer` callback is invisible to the sensor.
For images with a shell entrypoint script, this is the **entire entrypoint phase** —
not just the application's init, but the interpreter, the entrypoint script itself,
and every tool it calls.

Known affected paths for `nginx:1.25-alpine`:

| Path | Why it's missed |
|------|----------------|
| `/docker-entrypoint.sh` | Entrypoint script exec'd before NRI fires |
| `/docker-entrypoint.d/` (all scripts) | Sub-scripts run by entrypoint before NRI fires |
| `/bin/sh` | Shell interpreter for the entrypoint |
| `/bin/grep`, `/bin/sed`, `/bin/touch`, etc. | Busybox tools called by entrypoint scripts |
| `/run/nginx.pid` | Pid file written by master before NRI fires |
| `/var/run` | Symlink `/var/run → /run`; needed for pid file path |
| `/var/log/nginx/access.log` | Opened by master before first worker forks |
| `/var/log/nginx/error.log` | Same as above |
| `/var/cache/nginx/` | Temp subdirectories created at startup |

> **Note on empty directories:** `/var/cache/nginx/` subdirs and `/var/run` are empty
> at startup — they are created by nginx at runtime, not present as files in the image.
> `--include` skips empty directories, so these cannot be added via `--include`. Instead,
> provide them as writable mounts at container runtime:
> `docker run --tmpfs /var/cache/nginx --tmpfs /var/run ...`

### Risk level

**Low — broken image, not a security gap.**

The missed paths are empty directories and a pid file. No executable code, no shared
libraries, no secrets. A hardened image missing them will fail to start (nginx exits
with `mkdir() failed (2: No such file or directory)` or similar), not silently degrade.
The failure is loud and immediate, not subtle — and it is caught by `nginx -t` before
the container ever serves traffic.

### Now machine-detectable (schema v2)

The race still exists — nothing below eliminates it — but as of profile schema v2
it is **machine-detectable per container**. The sensor records its cgroup attach
time and the container's first observed exec, and emits a
`coverage.process_start_observed` marker in the profile. It is `true` only when
the sensor attached via the NRI `StartContainer` hook (before the runtime started
the workload), observed an exec, and its recorded attach time strictly precedes
that exec. Any uncertainty resolves to `false`. A container the sensor adopts
after it was already running, via NRI `Synchronize` (the missed-start case), is
always marked `false`.

Downstream coverage scoring uses this marker to treat startup code paths as
systematically missing when it is `false`, instead of silently assuming full
coverage. See [profile-schema/README.md](profile-schema/README.md#coverage-r2--process-start-coverage-marker)
for the exact semantics and the deliberate toward-`false` bias. The marker
reports the gap; it does not close it — the workarounds below remain the way to
recover the missed paths.

### Current workaround

**Step 1:** After the container starts, trigger `nginx -s reload`. This causes nginx to
re-exec its workers, generating new `execve` events while the cgroup is registered. The
nginx binary itself is now observed with `source: "direct"`.

```bash
# While the container is running and sensor is active:
sudo crictl exec $CTR nginx -s reload
```

**Step 2 (preferred):** Use `--include` in the `harden build` command to cover the full
entrypoint phase. `--include` adds every regular file and file symlink found under the
path in the source image layers. Entries appear as `source: "directory-inclusion"` with
**no confidence penalty**.

```bash
harden build \
  --manifest profiles/<container-id>/files.json \
  --source   nginx:1.25-alpine \
  --output   /tmp/nginx-hardened \
  --include  /bin \
  --include  /sbin \
  --include  /docker-entrypoint.sh \
  --include  /docker-entrypoint.d \
  --include  /var/log/nginx
```

`/bin` and `/sbin` cover all busybox tools without enumerating them individually.
`/docker-entrypoint.sh` and `/docker-entrypoint.d` add the entrypoint and its sub-scripts.
`/var/log/nginx` adds the `error.log → /dev/stderr` and `access.log → /dev/stdout` symlinks.

For empty dirs that nginx creates at runtime (`/var/cache/nginx`, `/var/run`), use
`--tmpfs` at container runtime — `--include` cannot add empty directories:

```bash
docker run --rm --tmpfs /var/cache/nginx --tmpfs /var/run <hardened-image> nginx -t
```

**Step 2 (alternative — for audit traceability):** Add the missed paths manually with
`source: "manual"` and an `included_because` field. This incurs a confidence penalty
but embeds the reason in the manifest for SBOM propagation.

```json
"/var/log/nginx/access.log": {
  "source": "manual",
  "access_modes": ["w"],
  "first_seen": "0001-01-01T00:00:00Z",
  "last_seen": "0001-01-01T00:00:00Z",
  "count": 0,
  "included_because": "startup-race: opened by nginx master before cgroup registration"
},
"/var/cache/nginx": {
  "source": "manual",
  "access_modes": [],
  "first_seen": "0001-01-01T00:00:00Z",
  "last_seen": "0001-01-01T00:00:00Z",
  "count": 0,
  "included_because": "startup-race: nginx creates client_temp/proxy_temp etc. here on startup"
}
```

### Effect on confidence score

The presence of `manual` entries with `startup-race` in their `included_because` field
indicates the profiling window did not capture startup. The confidence scorer applies
a penalty per such entry (−3/entry, cap −12, stacking with the base manual-entry penalty),
reducing the overall score. To maximise confidence:

- Trigger a reload during profiling (captures the binary via `execve`)
- Keep the `included_because` value accurate — it is a signal, not a comment

See [CONFIDENCE.md](CONFIDENCE.md) for the full penalty table and fix suggestions.

### Long-term direction

A `BPF_LSM` hook on `security_file_open` fires earlier in the kernel path than the NRI
`StartContainer` userspace callback. This would capture all file opens from container
start, eliminating the race entirely.

---

## 2. Static content not accessed during profiling

### What happens

Files served via HTTP (HTML, CSS, images, JS bundles, error pages) are only observed if a
client request arrives during the profiling window. If the container runs but receives no
traffic to a given endpoint, those files never generate an `openat` event and never appear
in the manifest. The hardened image will be built without them.

### Risk level

**Expected behaviour, not a bug.**

The Tracepod value proposition is: your minimised image contains exactly what your
production workload actually needed at runtime. A file that receives zero requests during
profiling is, by definition, not needed during that profiling window. The question is
whether the profiling window is representative of real production traffic.

### Current workaround

Send synthetic requests during the profiling window:

```bash
# While the container is running and sensor is active:
curl http://<container-ip>/
curl http://<container-ip>/50x.html
```

Or use `--include` to force-include the entire static content directory at build time:

```bash
harden build \
  --manifest profiles/<container-id>/files.json \
  --source   nginx:1.25-alpine \
  --output   /tmp/nginx-hardened \
  --include  /usr/share/nginx/html
```

This adds every regular file found under `/usr/share/nginx/html` in the source image
layers with `source: "directory-inclusion"`. Directory-inclusion entries are **not**
penalised by the confidence scorer — they are an explicit operator choice, not a sensor
coverage gap.

### Effect on confidence score

Manual entries added for unobserved static content receive the standard manual-entry
penalty (−5/entry, cap −25). To minimise penalties: send requests during profiling, or
use `--include` (which is not penalised) instead of `source: "manual"`.

See [CONFIDENCE.md](CONFIDENCE.md) for the full penalty table.

---

## 3. dlopen() on uninvoked code paths

### What happens

`dlopen()` — used for plugin loading, JVM native libraries, Python `ctypes`, OpenSSL engines,
and other runtime-loaded modules — is not reflected in the ELF `DT_NEEDED` section. The
`harden build` ELF dependency resolver reads static metadata and cannot predict what a binary
will load at runtime via `dlopen`.

### Risk level

**Lower than it appears — the sensor handles the common case better than static analysis.**

When `dlopen()` is called, the kernel maps the `.so` file into the process address space
with `PROT_EXEC`. The sensor's `mmap` kprobe captures this and records the library
path in the manifest with `source: "direct"` and `access_modes: ["m"]`.

This means the sensor resolves dlopen'd libraries dynamically, which is **strictly better
than any static resolver** for the common case: it catches conditional `dlopen()` calls that
static analysis can never reliably detect — including those guarded by feature flags, config
files, or environment variables.

The **genuine residual risk** is a `dlopen()` call that only fires on a code path not
exercised during profiling: an error handler, a quarterly batch step, a disaster-recovery
module. This is the same incomplete-profiling-window problem as limitations 1 and 2.

### Current workaround

Exercise all `dlopen`-triggering code paths during the profiling window. If specific paths
are untestable during profiling (e.g. a disaster-recovery plugin), use `--include` to
force-include the plugin directory:

```bash
harden build \
  --manifest profiles/<container-id>/files.json \
  --source   myapp:latest \
  --output   /tmp/myapp-hardened \
  --include  /usr/lib/myapp/plugins
```

Or add individual library paths manually:

```json
"/usr/lib/aarch64-linux-gnu/libssl.so.3": {
  "source": "manual",
  "access_modes": ["m"],
  "first_seen": "0001-01-01T00:00:00Z",
  "last_seen": "0001-01-01T00:00:00Z",
  "count": 0,
  "included_because": "dlopen: loaded by disaster-recovery plugin, not exercised during profiling"
}
```

**Known limitation with `--include` and shared libraries:** `.so` files added via `--include`
do not receive a second ELF resolution pass — their `DT_NEEDED` dependencies are not
automatically resolved. If the included library has its own dependencies, add those
explicitly or use `--include` on the library's directory too.

### Effect on confidence score

`dlopen`-sourced libraries appear as `source: "direct"` with `access_modes: ["m"]` — they
are indistinguishable from statically-linked libraries in terms of confidence, because the
sensor observed them actually loading. The risk only arises for paths _not_ exercised.
Manual entries added for unobserved dlopen paths receive the standard manual-entry penalty.

See [CONFIDENCE.md](CONFIDENCE.md) for the full penalty table.

---

## 4. Event loss under buffer pressure

### What happens

The sensor moves every file-open, exec, and exec-mmap event from the kernel
through a BPF ring buffer to a single userspace consumer. Under a high enough
event rate — a workload opening files faster than the consumer drains them — the
ring buffer fills and the kernel **drops** events: `bpf_ringbuf_reserve()`
returns `NULL` and the event is gone. Smaller drop sources exist too (a faulting
userspace path pointer, a malformed record, an event arriving in the brief race
between the BPF allowlist and the userspace aggregator at container start/stop).

A dropped open is invisible by nature: the file was accessed, but the manifest
never learns it. The danger is not the missing file alone — it is the *silence*.
A busy window with drops looks, from the manifest, like a quiet window. A
downstream coverage scorer that rewards "discovery has flattened" can score a
lossy window *higher* than a clean one, exactly when observation quality was
worse.

### Risk level

**Low for image correctness, but it can poison "not loaded" claims.** A drop
never adds a wrong file (fail-safe for minimisation — a dropped open just means a
file might be missing, caught by testing the hardened image). The real risk is to
*consumers that reason from absence*: treating "not observed" as "not loaded" is
only valid when nothing was dropped.

### Now machine-visible (schema v3)

As of profile schema v3 the sensor **counts event loss at every audited drop
point** and reports it in the profile's top-level `event_loss` block:

```jsonc
"event_loss": {
  "total": 0,                       // HARD-loss gate: nonzero ⇒ this window was lossy
  "by_stage": {                     // where the hard loss happened (diagnosis only)
    "bpf_reserve_failed": 0,        // ring buffer full (the primary cause)
    "decode_failed": 0,             // malformed record skipped
    "untracked_cgroup": 0           // start/stop race
  },
  "tolerated": {                    // counted, consumer-gated, excluded from total
    "path_read_failed": 1           // openat filename pointer faulted → open unidentified
  },
  "not_instrumented": []            // empty ⇒ every in-scope drop point was counted
}
```

The counts are **window-level**, not per-container: a buffer drop cannot be
attributed to one container, so any loss in a window taints every container
observed in it (the conservative direction). `total: 0` is a positive claim
("instrumented everywhere, lost nothing on the hard paths"), never "didn't count"
— a drop point that could not be instrumented is named in `not_instrumented`
instead of reading a false zero.

The openat **path-read fault** (`bpf_probe_read_user_str()` faulting on the
filename pointer before its page is present) is a real lost observation — the file
open goes unidentified. As of schema v3 it is **counted as a tolerated category**
(`event_loss.tolerated.path_read_failed`), not folded into `total`: it has a
load-independent idle floor (0–2 per container) that would otherwise put a
permanent floor under the strict-zero hard-loss gate and defeat it. A consumer
gates it with its own configurable ceiling (never zero) and surfaces the count.
(In OSS-4 this fault was *excluded* from the loss accounting entirely; OSS-4b made
it visible-but-separately-gated, because "total 0, nothing reported" wrongly read
as "nothing lost" while opens went unidentified.) See
[profile-schema/README.md](profile-schema/README.md#event_loss-v3--window-level-event-loss-counters)
for the full field reference, the loss-point audit, and consumer guidance.

The limitation itself **remains**: loss can still happen under buffer pressure
(raise the ring-buffer size, lower the event rate, or profile under representative
rather than worst-case load). What changed is that the silence ended — a lossy
window now announces itself, so a consumer can refuse to draw "not observed ⇒ not
loaded" conclusions from it.

### Current workaround

Profile under representative load; for known-bursty workloads the ring-buffer
size is a build-time constant in `internal/probe/openat.c` (default 256 KB) and
can be raised. The sensor's `--ringbuf-bytes` flag overrides it (it exists to
*shrink* the buffer for the induced-loss test fixture, but accepts larger values
too). Most importantly: **check `event_loss.total` before trusting absence.**

---

## Summary

| Gap | Security risk | Image breakage risk |
|-----|--------------|---------------------|
| CRI-only profiling (silent miss for docker/nerdctl targets) | None | N/A (no manifest written) |
| NRI startup race (entire entrypoint + init phase) | None | High (startup failure) |
| Static content not served during profiling | None | Low (404s, not crash) |
| `dlopen()` on uninvoked code paths | Low | Low |
| Event loss under buffer pressure | None | Low (fail-safe) — but taints "not loaded" claims; now counted in `event_loss` |
| Stat-only existence checks (interpreter source files) | None | Was high for Python (startup crash); closed by the runtime companion resolver — residual risk for other stat-probe patterns |

### The underlying pattern

## 5. Final-generation loss on ungraceful sensor exit (SIGKILL)

### What happens

A container's observations are accumulated in an in-memory aggregator and POSTed to
the controller (or written to disk) only when the container stops, and — since the
OSS-5 fix — also when the sensor receives `SIGTERM`/`SIGINT` (it now flushes every
in-flight profile before exiting). The owning workload is resolved and cached at
container **start**, so the final POST no longer depends on a live Kubernetes lookup
that races pod/ReplicaSet garbage collection at stop time (the original OSS-5 loss).

The remaining window: if the sensor process is **`SIGKILL`ed** (OOM-kill, `kubectl
delete pod --force --grace-period=0`, node hard-power-loss) it has no opportunity to
flush. Every container being tracked at that instant loses the observations
accumulated since its last successful POST.

### Risk level

**Low and bounded, but it produces a *truncated* profile, not a wrong one.** The
loss is always in the conservative direction — fewer observed paths than truth —
which is exactly the error a downstream gate must not silently trust.

### Workaround / downstream contract

- Give the sensor DaemonSet a non-trivial `terminationGracePeriodSeconds` so the
  graceful-flush path (SIGTERM) is used on rollouts and drains.
- A profile produced across a `SIGKILL` of the sensor must be treated as
  **truncated**: it must **not** yield a `not_affected`/`not_loaded` verdict
  downstream (same philosophy as the event-loss gate in §4 — absence of observation
  in a truncated window is not evidence of absence of use).

### Long-term fix direction

Periodic incremental flush (durable spool) so the unflushed delta is bounded by the
flush interval rather than by the whole container lifetime. Tracked separately; the
stop-path and SIGTERM-path correctness (OSS-5) is the prerequisite and is now in place.

## 6. Existence checks (stat) are invisible — the interpreter source-file blind spot

### What happens

The sensor traces `openat`, `exec`, and `mmap` — it cannot see files a process merely
`stat(2)`s. Some runtimes prove a file is required without ever opening it. CPython is
the acute case: importing a module with a warm bytecode cache **stats** `<pkg>/<mod>.py`
and **opens** only `<pkg>/__pycache__/<mod>.cpython-NN.pyc` — yet at runtime it refuses
that cached pyc when the sibling source is missing. A minimized image containing exactly
the observed files therefore cannot even `import encodings` and dies in interpreter
startup (`init_fs_encoding: no codec search functions registered`).

### Risk level

**Was high for Python workloads (guaranteed startup crash); now closed for the known
Python case.** The general stat-blindness remains for other existence-probe patterns
(Node module-resolution stat storms, config-file probing chains).

### Current mitigation

- The hardener's **runtime companion resolver** (`hardener/runtime.go`) runs after ELF
  resolution and deterministically adds the implied files: every `__pycache__` pyc adds
  its sibling `.py` when present in the source image (`source=inferred-runtime`, with
  `inferred_from` audit trail). It also normalizes transient atomic-write pyc names
  (`<mod>.pyc.<digits>`) to their final path.
- Curated per-runtime baseline presets (dashboard: `runtime-python3.11/12/13`) cover
  known-but-not-derivable gaps such as `encodings/` and `lib-dynload/`.
- Sandbox validation remains the safety net: a hardened image that cannot boot fails
  validation before any push.

### Long-term fix direction

Optional stat-family tracing (`newfstatat`/`statx` kprobes) behind a sensor flag, with
the schema-v3 event-loss counters guarding ring-buffer pressure. High event volume and
verifier risk — needs careful review before default-on.

---

All three gaps are instances of **incomplete profiling window coverage**. The confidence
score surfaces this systematically:

| Signal | Effect on confidence score |
|--------|---------------------------|
| Short profiling window (below recommended minimum) | Penalty |
| `manual` entries in manifest without an observed counterpart | Penalty per entry |
| `startup-race` in `included_because` | Additional penalty per entry |
| `directory-inclusion` entries via `--include` | **No penalty** — explicit operator choice |
| `inferred-elf` entries with no `direct` parent in the manifest | Audit note only (no penalty) |

A confidence score of 100 means all known gaps were mitigated during the profiling session.
Scores below 100 indicate which gaps remain open and what would close them. See
[CONFIDENCE.md](CONFIDENCE.md) for the complete scoring reference and fix suggestions.

### The right mental model

Tracepod is not a static analyser. It is a runtime observer. Its output is only as complete
as the workload it observed. Profile your application under the same load pattern it will
see in production, and your hardened image will be correct. Profile it while it sits idle
and you will need to fill the gaps manually — which is still better than a static tool that
guesses.
