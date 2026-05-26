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

## Summary

| Gap | Security risk | Image breakage risk |
|-----|--------------|---------------------|
| CRI-only profiling (silent miss for docker/nerdctl targets) | None | N/A (no manifest written) |
| NRI startup race (entire entrypoint + init phase) | None | High (startup failure) |
| Static content not served during profiling | None | Low (404s, not crash) |
| `dlopen()` on uninvoked code paths | Low | Low |

### The underlying pattern

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
