# Tracepod

**eBPF-based container hardening for Kubernetes.**

Tracepod observes what a running container actually uses at runtime — files, libraries,
shared objects — via eBPF kernel tracing, then builds a minimised OCI image containing
only those components. The result is a smaller attack surface: fewer files, fewer
packages, fewer CVEs.

## How it works

```
┌─────────────────────────────────────────────────────────┐
│                     Kubernetes cluster                   │
│                                                          │
│  eBPF sensor                                             │
│  (DaemonSet)    ──openat() kprobe──►  file manifest      │
│                                            │             │
│                                            ▼             │
│                                       harden CLI         │
│                                            │             │
│                                    minimised OCI image   │
└─────────────────────────────────────────────────────────┘
```

1. **Profile** — the sensor attaches an eBPF kprobe to `openat()` and records every file
   a container opens, filtered by cgroup namespace to the target container only
2. **Harden** — the hardener reads the manifest and builds a new OCI image containing
   only the observed files, resolved ELF dependencies, and any explicitly included paths
3. **Validate** — boot the hardened image (`harden build --smoke-test`) or run your own smoke test before shipping
4. **Publish** — push the hardened image to your registry

## Components

| Binary | Platform | Description |
|--------|----------|-------------|
| `sensor` | Linux only | eBPF DaemonSet — profiles running containers |
| `harden` | Linux + macOS | Builds minimised OCI images from manifests |
| `tracepod` | Linux + macOS | CLI client for the Tracepod controller API — see note below |

> **`tracepod` CLI and the controller:** The `tracepod` binary connects to a separate
> server-side controller component that is not included in this repository. You do not
> need it for standalone or Kubernetes-helm usage — retrieve manifests directly from the
> sensor pod via `kubectl exec` (see Quick start below). The controller is required only
> for multi-node aggregation and the managed UI.

### Reachability & CVE reporting

`tracepod cve-report <workload>` renders a **reachability report**: for every CVE
a scanner finds in your image, whether the affected package was actually *loaded*
during the profiling window — so you triage the CVEs your workload exercises, not
the hundreds it never touches. See the
[reachability quickstart](docs/reachability-quickstart.md) and the
[`cve-report` CLI reference](docs/cli-cve-report.md).

| Capability | Free | Pro |
|------------|------|-----|
| `cve-report` reachability report (loaded / not-loaded classification) | ✅ | ✅ |
| `--findings` upload (classify an existing Trivy/Grype scan) | ✅ | ✅ |
| VEX `not_affected` export from `not_loaded` findings | — | ✅ |

The CLI is a pure rendering client: all classification and scoring happen in the
controller; the analysis engine is never duplicated client-side.

> **Important:** Only containers managed by Kubernetes (kubelet → containerd) or
> started via `crictl` are profiled. Containers started with `docker run`,
> `nerdctl run`, or `docker-compose` are silently ignored because the sensor
> integrates with the containerd NRI interface, which `dockerd` does not use.
> See [Known Limitations](docs/KNOWN-LIMITATIONS.md) for details.

## Prerequisites

- Kubernetes cluster with containerd 1.7+ as the runtime
- NRI enabled in containerd (see [NRI setup](#enable-nri-in-containerd) below)
- Helm 3 (for the Kubernetes deployment path)
- `skopeo` or `crane` for importing the hardened image into your registry or daemon

### Enable NRI in containerd

NRI must be enabled before installing the sensor — without it the sensor connects
but no containers are ever profiled:

```toml
# /etc/containerd/config.toml on each node
[plugins."io.containerd.nri.v1.nri"]
  disable = false
```

Then restart containerd: `sudo systemctl restart containerd`

Verify:
```bash
./hack/discovery-probe.sh
# exit 0 means NRI is reachable; exit 1 means it's still not enabled
```

## Install

### From GHCR (container image)

```bash
# Sensor DaemonSet image (used by Helm chart) — pin to a release tag
docker pull ghcr.io/tracepod/tracepod-sensor:v0.2.10
```

### From goreleaser releases

Download pre-built binaries from the [Releases](https://github.com/tracepod/tracepod/releases) page.

### Build from source

```bash
git clone https://github.com/tracepod/tracepod.git
cd tracepod
CGO_ENABLED=0 go build ./cmd/harden/
# sensor requires Linux + BPF toolchain — see CONTRIBUTING.md
```

## Quick start

### Kubernetes (recommended)

> **Profiling scope:** Once installed, the sensor profiles **every** container
> kubelet/containerd creates on the node — including `kube-system`. There is no
> per-pod opt-in (no label, annotation, or namespace selector). You filter
> downstream by mapping container IDs back to pods (see step 4 below). In
> controller mode (`--controller-url`), pods without a Deployment/StatefulSet
> owner are silently dropped before upload; in standalone mode (`--profile-dir`,
> the default), every stopped container produces a manifest.

```bash
# 0. Check that a node can actually run the sensor BEFORE installing —
#    the sensor's only discovery mechanism is containerd's NRI; if it's
#    unreachable the sensor now refuses to run rather than silently
#    tracing nothing (see "NRI must be enabled" above).
#
#    Directly on the node:
./hack/discovery-probe.sh
#
#    Or via a node-debug pod, if you don't have SSH/node access (the host
#    filesystem is bind-mounted at /host in the debug pod, not at /, so
#    HOST_ROOT must be set):
#      kubectl debug node/<name> -it --image=ubuntu:24.04 -- bash
#      # then, inside the debug pod:
#      apt-get update -qq && apt-get install -y -qq curl socat
#      curl -fsSLO https://raw.githubusercontent.com/tracepod/tracepod/v0.2.10/hack/discovery-probe.sh
#      HOST_ROOT=/host bash discovery-probe.sh
#
#   exit 0  NRI reachable — the sensor will work
#   exit 1  NRI unreachable — the sensor would trace nothing (see its remediation output)
#   exit 2  probe could not run (not a Linux host)

# 1. Enable NRI in containerd on each node (see Prerequisites above)

# 2. Install the sensor DaemonSet
helm install tracepod ./helm/tracepod \
  --namespace tracepod \
  --create-namespace

# 3. Exercise your workload — the sensor profiles containers while they run
#    Profiles are written to /var/lib/tracepod/profiles/<container-id>/files.json
#    on the node when the container stops

# 4. Retrieve the manifest — find the sensor pod on the node your container
#    ran on (a multi-node cluster has one sensor pod per node, so exec'ing
#    "daemonset/tracepod-sensor" picks an arbitrary one and may miss the file):
NODE=$(kubectl get pod <your-pod> -o jsonpath='{.spec.nodeName}')
SENSOR=$(kubectl -n tracepod get pod \
  -l app.kubernetes.io/name=tracepod-sensor \
  --field-selector spec.nodeName=$NODE \
  -o jsonpath='{.items[0].metadata.name}')
kubectl -n tracepod exec $SENSOR -- \
  cat /profiles/<container-id>/files.json > manifest.json

# Map container IDs to pod names:
kubectl get pods -A -o jsonpath=\
  '{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[*].containerID}{"\n"}{end}' \
  | sed 's|containerd://||g'

# 5. Build the hardened image
harden build \
  --manifest manifest.json \
  --source nginx:1.25-alpine \
  --output /tmp/hardened-nginx

# 6. Import into your local Docker daemon and validate
skopeo copy oci:/tmp/hardened-nginx docker-daemon:myapp:hardened
docker run --rm myapp:hardened nginx -t   # replace with your app's smoke test

# Or push directly to a registry:
harden build \
  --manifest manifest.json \
  --source nginx:1.25-alpine \
  --output /tmp/hardened-nginx \
  --push myregistry.com/myapp:hardened
```

### What a successful build looks like

`harden build` prints a summary when it completes. A healthy run looks like:

```
Source:      nginx:1.25-alpine (sha256:fac2017f...)
Auth:        anonymous
Registry:    docker.io
Files:       312 (289 direct, 23 inferred-elf, 0 manual/scratch-compat)
Confidence:  88/100 (High)
Layer:       8.3 MB (sha256:...)
OCI layout:  /tmp/hardened-nginx
Next:        skopeo copy oci:/tmp/hardened-nginx docker-daemon:myapp:hardened
Warning:     /etc/resolv.conf not found in image layers (bind-mounted at runtime — OK)
```

Key things to check:
- **Confidence** should be 70+ for a production build; see [docs/CONFIDENCE.md](docs/CONFIDENCE.md) for what lowers the score
- **Files** count should be non-zero — a count of 0 direct observations means the sensor was not active or profiling did not capture any file-opens
- `resolv.conf` absent is **expected** — the container runtime provides it; exit code 2 is returned only for other missing scratch-compat files
- If `harden build` exits 0 but the hardened image fails to start, run [`harden diagnose`](#when-a-hardened-image-fails-harden-diagnose-and-harden-explain) on its log, or run with `--verbose` and use `--include` to add missing directories

### Standalone (single Linux host, no Kubernetes)

The sensor can run directly on a Linux host and profile containers started via `crictl`:

```bash
# 0. Check that this host can actually run the sensor BEFORE installing —
#    the sensor's only discovery mechanism is containerd's NRI; if it's
#    unreachable the sensor now refuses to run rather than silently
#    tracing nothing (see "NRI must be enabled" above).
#
#    On a bare host the probe runs directly — no HOST_ROOT needed
#    (that's only for node-debug pods bind-mounting the host filesystem):
./hack/discovery-probe.sh
#
#    Or, if you don't have the repo checked out on this host:
#      curl -fsSLO https://raw.githubusercontent.com/tracepod/tracepod/v0.2.10/hack/discovery-probe.sh
#      bash discovery-probe.sh
#
#   exit 0  NRI reachable — the sensor will work
#   exit 1  NRI unreachable — the sensor would trace nothing (see its remediation output)
#   exit 2  probe could not run (not a Linux host)

# 1. Enable NRI in containerd (see Prerequisites above)

# 2. Run the sensor binary (Linux only, requires root / CAP_BPF + CAP_SYS_ADMIN)
sudo ./sensor \
  --profile-dir /tmp/tracepod-profiles \
  --verbose

# 3. Start a container via crictl (not docker run — see warning above)
sudo crictl run container.json sandbox.json

# 4. Stop the container — this triggers manifest write
sudo crictl stop <container-id>

# 5. The manifest is at /tmp/tracepod-profiles/<container-id>/files.json
harden build \
  --manifest /tmp/tracepod-profiles/<container-id>/files.json \
  --source nginx:1.25-alpine \
  --output /tmp/hardened-nginx

# 6. Import and validate
skopeo copy oci:/tmp/hardened-nginx docker-daemon:myapp:hardened
docker run --rm myapp:hardened nginx -t
```

## Key `harden build` flags

| Flag | Description |
|------|-------------|
| `--manifest <path>` | Path to the sensor manifest JSON (required) |
| `--source <ref>` | OCI image reference used during profiling (required) |
| `--output <dir>` | Output directory for the OCI image layout (required) |
| `--push <ref>` | Push the hardened image to this registry reference after building |
| `--platform <os/arch>` | Image platform — **must match your deployment target** (default: `linux/amd64`) |
| `--include <path>` | Force-include all files under this in-image directory (repeatable) |
| `--mkdir <path>` | Create an empty directory even if absent from source (repeatable) |
| `--touch <path>` | Create an empty file even if absent from source (repeatable) |
| `--verbose` | Print full confidence penalty breakdown and ELF audit warnings |
| `--sbom` | Generate CycloneDX and SPDX SBOMs in the output directory |
| `--min-profile-duration` | Minimum window for confidence scoring (default: 10m) |
| `--allow-empty` | Build even when the manifest has zero `direct` (eBPF-observed) entries (default: refuse — see exit code `3` below) |
| `--inventory-out <path>` | Write the file inventory JSON to this path instead of `<output>/inventory.json` |
| `--no-inventory` | Do not record or write the file inventory |

Run `harden build -help` or `harden extract -help` for the full flag reference.

**Exit codes:**
- `0` — success
- `1` — fatal error (missing required flags, pull failed, unresolved ELF dependencies)
- `2` — non-fatal warning: a scratch-compat file (other than `resolv.conf`) was absent from the source image layers; `resolv.conf` absence is expected and exits `0`
- `3` — the manifest has zero `direct` (eBPF-observed) entries — the sensor wasn't active or the profiling window captured nothing, and a build from inferred/manual entries alone is very likely broken; pass `--allow-empty` to build anyway

## File inventory

Every `harden build` records a file inventory and writes it to
`<output>/inventory.json` (override with `--inventory-out <path>`, disable with
`--no-inventory`). It describes both the source image filesystem (after layer
whiteouts are applied) and the hardened image layer, so every path that exists in
either tree is listed once with what it is in each:

```json
{
  "version": 2,
  "source_digest": "sha256:...",
  "hardened_digest": "sha256:...",
  "files": [
    {"path": "/bin", "type": "symlink", "link_target": "usr/bin", "in_hardened": true, "in_source": true, "hardened_type": "dir"},
    {"path": "/bin/app", "in_hardened": true, "in_source": false, "hardened_type": "file"},
    {"path": "/usr/bin/app", "type": "file", "in_hardened": false, "in_source": true},
    {"path": "/usr/bin/sh", "type": "symlink", "link_target": "busybox", "in_hardened": false, "in_source": true}
  ]
}
```

- `path` is absolute in the image, `/`-rooted, with no trailing slash; entries are sorted by `path`.
- `in_source` is true when the path exists in the source image. `type` and `link_target`
  describe it there and are omitted when it does not.
- `type` is `file`, `dir`, `symlink` or `other` (device, fifo, socket). Hardlinks are
  extracted as regular files and reported as `file`.
- `link_target` is the raw link value (relative or absolute, never resolved); symlinks only.
- `in_hardened` is true when the path exists in the hardened layer, and `hardened_type` /
  `hardened_link_target` describe it there. The hardened tree is read back from the built
  layer itself. It can differ from the source tree: the layer writes each kept path under
  the name it was accessed by and creates its parent directories as real directories, so
  on a merged-`/usr` image a library opened as `/lib/x/libc.so.6` is kept as
  `/lib/x/libc.so.6` with `/lib` a directory, while the source has `/lib -> usr/lib` and
  the file at `/usr/lib/x/libc.so.6`. Paths created by `--mkdir`/`--touch` and the parent
  directories of every kept path are listed as hardened-only entries.

Version 1 documents (written by earlier releases) list source paths only, without
`in_source`, `hardened_type` or `hardened_link_target`; `in_hardened` there means the exact
path is in the layer, and a directory counts when it contains a kept path.
`hardener.ReadInventory` / `hardener.DecodeInventory` read both versions and set
`in_source` for version 1 entries; `InventoryFile.DescribesHardenedTree` tells them apart.

A failure to collect the inventory only prints a warning; the build still succeeds. A
failure to write the file exits non-zero. Library callers opt in with
`hardener.BuildOptions{RecordInventory: true}` and read `BuildResult.Inventory`
(`BuildResult.InventoryErr` carries a collection failure).

## When a hardened image fails: `harden diagnose` and `harden explain`

`harden diagnose` reads the log of a hardened container that fails and suggests
the `harden build` flags that restore what it is missing. It only suggests paths
that exist in the source image and were removed by the build (from the build's
`inventory.json`), and it never rebuilds anything itself.

```bash
# --smoke-test saves the container log to <output>/smoke.log when it fails
harden build --manifest files.json --source nginx:alpine --output /tmp/h --smoke-test
# error: smoke test failed: container exited 1 ...
# Hint: harden diagnose --output /tmp/h --log /tmp/h/smoke.log

harden diagnose --output /tmp/h --log /tmp/h/smoke.log
# Likely missing (from log):  /etc/nginx/mime.types  [deterministic]
# Likely missing (from log):  /var/cache/nginx       [deterministic]
# Re-run with:
#   harden build ... --include /etc/nginx/mime.types --mkdir /var/cache/nginx

# Any log works; use - for stdin
kubectl logs deploy/myapp | harden diagnose --output /tmp/h --log -
```

Paths the log names directly (a quoted path, or a file name) are reported as
`[deterministic]`. Weaker matches, such as a Python module `email.mime` that maps
to a directory, are only ranked when a model is configured. If nothing matches,
the failure is probably environmental (network, credentials, configuration).
`--inventory` points at an inventory written with `--inventory-out`; `--json`
prints machine-readable output. Exit code 0 means the command ran (with or
without suggestions); 2 means a usage or input error.

`harden explain --output <dir>` summarises what a build removed and kept: path
counts, the removed packages with the most paths, and removed shells, package
managers, network tools, docs, test directories and locale data. Add
`--manifest files.json` to count kept paths by observation source.

Both commands work without any model. Optionally, bring your own model: an
OpenAI-compatible endpoint (Ollama, vLLM, LiteLLM, OpenRouter, ...) or the
Anthropic API. Then `diagnose` also lets the model pick among the weaker matches
(it can only select from that list; anything else is rejected), and `explain`
adds a short plain-English summary checked against the facts it was given. Logs
are redacted before they are sent. Nothing is sent unless a provider is
configured, and `--no-ai` turns it off for one run:

```bash
export TRACEPOD_AI_PROVIDER=openai-compatible
export TRACEPOD_AI_BASE_URL=http://localhost:11434/v1   # Ollama
export TRACEPOD_AI_MODEL=qwen2.5:7b-instruct
harden diagnose --output /tmp/h --log /tmp/h/smoke.log

# or the Anthropic API
TRACEPOD_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=... harden explain --output /tmp/h
```

See [docs/ai.md](docs/ai.md) for every setting.

## Confidence scoring

The hardener scores each build from 0–100 based on profiling completeness.
A short profiling window, manual entries, or no observations all reduce the score.
See [docs/CONFIDENCE.md](docs/CONFIDENCE.md) for the full breakdown.

```
Confidence:  82/100 (High) — short profiling window; startup race (4 paths)
```

## Interim profile snapshots

By default the sensor reports a container's profile only when the container stops (or when
the sensor itself shuts down), so a long-running workload reports nothing until it
restarts. Set `--snapshot-interval` to have the sensor also POST periodic interim snapshots
to `--controller-url` while the container runs:

| Flag | Default | Description |
|------|---------|-------------|
| `--snapshot-interval <duration>` | `0` (off) | POST a cumulative interim profile snapshot for each running container at this interval. Must be `0` or at least `10s`. Requires `--controller-url`; ignored (with a log line) without it. Helm: `sensor.snapshotInterval`. |

Semantics:

- With the flag off (the default) behaviour is unchanged: no extra goroutine, no extra POSTs.
- Snapshots are **cumulative** for the observation window: every snapshot for a container
  carries the same `container_id` and `profile_start`, a later `profile_end`, and a file set
  that only grows. A later snapshot supersedes an earlier one.
- Interim snapshots have `profile_terminal: false`. The POST at container stop is the only
  one with `profile_terminal: true`, and it is always the last POST for that window: the
  sensor serialises a container's POSTs, so a stop waits for any in-flight interim POST and
  no interim POST starts after it. The shutdown flush on SIGTERM is also non-terminal.
- Only containers whose owning workload (Deployment/StatefulSet) was resolved at container
  start are posted. The interim path never does a live Kubernetes lookup and never posts for pods without a workload owner; those containers are reported at stop as usual.
- Each container's first snapshot is offset by a deterministic jitter in `[0, interval)`
  derived from its container ID, so a node's containers do not all POST at once.
- A failed POST never blocks event processing. It is logged (at most once per container per
  10 minutes) and the next scheduled snapshot, which is cumulative, supersedes it.
- Interim snapshots are POSTed only; they are not written to `--profile-dir`.
- Payload size grows with the number of observed paths (a cumulative snapshot of a large
  workload can be thousands of entries), so pick an interval accordingly. The receiving
  endpoint must tolerate repeated POSTs for the same window; a receiver that sums POSTs
  instead of replacing/merging by `profile_start` will over-count.

## Troubleshooting

### No profiles appear after the container stops

1. **Is NRI enabled?**
   ```bash
   ./hack/discovery-probe.sh
   ```
   Exit 0 means NRI is reachable. Exit 1 means it's disabled — see its remediation
   output and `docs/KNOWN-LIMITATIONS.md` §0.6; restart containerd after fixing it.

2. **Is the sensor connected?**
   ```bash
   kubectl logs -n tracepod daemonset/tracepod-sensor | tail -20
   ```
   Look for `NRI connected`. If absent, the plugin failed to register — NRI is likely
   disabled. Outside `--cgroup-path` mode the sensor now exits non-zero in that case, so
   the pod will be `CrashLoopBackOff`/not Ready instead of running quietly; check
   `--previous` logs if the container has already restarted.

3. **Was the container started via the CRI?**
   Only containers created by kubelet (Kubernetes pods) or `crictl` are profiled.
   `docker run`, `nerdctl run`, and `docker-compose` are not profiled. See
   [Known Limitations](docs/KNOWN-LIMITATIONS.md).

4. **Did the container stop?**
   By default profiles are written when the container stops, not while it is running. The
   sensor aggregates events during the container's lifetime and flushes them on stop. With
   `--snapshot-interval` and `--controller-url` it also POSTs interim snapshots while the
   container runs — see [Interim profile snapshots](#interim-profile-snapshots).

5. **Check which containers the sensor is tracking:**
   ```bash
   kubectl logs -n tracepod daemonset/tracepod-sensor | grep "tracking"
   # sensor: tracking  container=<id> cgroup=<n>
   ```

## Local end-to-end testing (Mac)

Mac contributors can run the full sensor → harden → validate pipeline locally using
the `k8s-dev` Lima VM, which provides Ubuntu 24.04 + Docker + kind — no Linux host required.

### One-time setup

```bash
# Create and start the VM (downloads ~500 MB; takes a few minutes)
limactl create --name k8s-dev infra/lima/k8s-dev.yaml
limactl start k8s-dev
```

The VM provisions Docker CE, kind v0.27.0, kubectl, helm, and Go 1.26. It mounts your
home directory writable, so the tracepod repo is immediately available inside.

### Run the e2e suite

```bash
make e2e
```

This runs `hack/e2e/run-e2e.sh` inside the Lima VM. It will:
1. Build the sensor Docker image (arm64, using committed BPF objects — no clang needed)
2. Create a kind cluster with NRI enabled in containerd
3. Deploy the sensor DaemonSet via Helm
4. Deploy nginx, exercise it, then scale it to 0 (triggering a manifest flush)
5. Run `harden build` to produce a FROM-scratch nginx image
6. Validate with `nginx -t` inside the hardened container

A successful run ends with:

```
══════════════════════════════════════
  PASS: tracepod e2e test complete
══════════════════════════════════════
```

### Flags

```bash
# Keep the kind cluster alive after the test (for kubectl debugging)
limactl shell k8s-dev -- bash -c "cd ~/work/tracepod && bash hack/e2e/run-e2e.sh --keep-cluster"
```

### CI

The same pipeline runs in GitHub Actions on every push to `main` via
`.github/workflows/e2e.yaml` (ubuntu-latest, amd64, no Lima VM needed).

### Kernel compatibility (Amazon Linux 2023)

EKS's default node OS is Amazon Linux 2023 (kernels 6.1 / 6.12 / 6.18
depending on AMI release), but local dev and CI only exercise Ubuntu kernels
(6.8, 6.17). `infra/lima/al2023-kernel.yaml` provisions a bare AL2023 VM
(kernel 6.1, no containerd/kubelet) to check that the sensor's BPF programs
load and its kprobes attach on AL2023's kernel build:

```bash
limactl start --tty=false --name=al2023-kernel infra/lima/al2023-kernel.yaml
limactl copy hack/kernel-compat.sh al2023-kernel:/tmp/kernel-compat.sh
limactl copy hack/discovery-probe.sh al2023-kernel:/tmp/discovery-probe.sh
limactl shell al2023-kernel -- sudo bash /tmp/kernel-compat.sh
limactl stop al2023-kernel   # leaves the VM in place for reuse
```

`hack/kernel-compat.sh` downloads the released sensor binary (or set
`SENSOR_BIN=/path/to/sensor` to use a local build), verifies BTF/cgroup v2
preconditions, confirms every kprobe symbol exists, confirms the sensor
attaches all of them (fatal `open probe:` error otherwise), cross-checks
`/sys/kernel/debug/kprobes/list`, and runs a synthetic workload through a
manually-allowed cgroup. Since v0.2.2 it also verifies end to end that
`--cgroup-path` records opens and execs for that cgroup (the userspace
recording gap it originally uncovered was fixed in v0.2.2).

`hack/kernel-compat.sh` only exercises BPF load/attach — it never runs a
containerd/kubelet/kind stack, so it can't catch a bug in NRI adoption, the
harden build, or smoke test. `infra/lima/al2023-e2e.yaml` provisions
a second AL2023 VM sized and provisioned like the Ubuntu `k8s-dev` VM (Docker,
kind, kubectl, helm, Go, syft) so the FULL `hack/e2e/run-e2e.sh` pipeline
(sensor DaemonSet, harden build, smoke test) can run against AL2023's
own kernel build, on each of EKS's three shipping kernels:

```bash
limactl start --tty=false --name=al2023-e2e infra/lima/al2023-e2e.yaml
hack/e2e/run-e2e-al2023.sh --kernel 6.1 --ref v0.2.10   # kernel switch is manual — see below
limactl stop al2023-e2e   # leaves the VM in place for reuse
```

`hack/e2e/run-e2e-al2023.sh` archives the given `--ref` with `git archive`,
ships it into the VM (no host mounts on this image), and runs the unmodified
released `run-e2e.sh` from that ref — except that the wrapper always overlays
the CURRENT WORKING TREE's `hack/e2e/run-e2e.sh` on top before running it
(sha256-verified in the wrapper's own output), so a harness fix in this repo
is exercised even when `--ref` pins an older tag. To switch kernels, install
with `dnf install -y kernel6.<NN>`, `grubby --set-default`, then
`limactl stop al2023-e2e && limactl start al2023-e2e`.

**2026-09-29 results** (worktree harness fix below, product code pinned at
tag `v0.2.2`):

| Kernel | Full e2e (`run-e2e.sh`) | `hack/kernel-compat.sh` |
|--------|--------------------------|--------------------------|
| 6.1.186-228.376.amzn2023  | PASS | ALL CHECKS PASSED |
| 6.12.103-129.197.amzn2023 | PASS | ALL CHECKS PASSED |
| 6.18.48-109.150.amzn2023  | PASS | ALL CHECKS PASSED |

The first two full-e2e attempts on this VM (6.1, 6.12) failed at
`coverage.adoption_mode=nri-sync, want nri-start`: `run-e2e.sh` had no wait
for the kind node to be Ready, and `kubectl rollout status daemonset/...`
returns success vacuously when the DaemonSet has zero desired pods — so on
this VM's nested-QEMU boot timing, nginx could start (and get adopted via an
NRI `Synchronize` scan instead of `StartContainer`) before the sensor was even
scheduled. This was a harness race, not a product bug: `nri-sync` was the
factually correct label for what happened. Fixed in `hack/e2e/run-e2e.sh` by
adding three explicit waits before Phase 4 (node Ready, DaemonSet
desired/ready count, sensor's "NRI connected" log line) — see the script's
inline comments for detail. All three AL2023 kernels above ran clean with the
fix.

## Documentation

- [Architecture](docs/architecture.md)
- [Confidence scoring](docs/CONFIDENCE.md)
- [Known limitations](docs/KNOWN-LIMITATIONS.md)
- [Contributing](CONTRIBUTING.md)
- [Helm chart](helm/tracepod/README.md)

## Licence

AGPL-3.0 — see [LICENSE](LICENSE).
