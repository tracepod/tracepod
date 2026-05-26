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
3. **Validate** — run the hardened image in a sandbox to confirm it behaves correctly
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
grep -E "^\s*disable\s*=" /etc/containerd/config.toml | grep nri
# Should print:   disable = false
# (or be absent — NRI is enabled by default in containerd 2.x)
```

## Install

### From GHCR (container image)

```bash
# Sensor DaemonSet image (used by Helm chart)
docker pull ghcr.io/tracepod/tracepod-sensor:latest
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
# 1. Enable NRI in containerd on each node (see Prerequisites above)

# 2. Install the sensor DaemonSet
helm install tracepod ./helm/tracepod \
  --namespace tracepod \
  --create-namespace

# 3. Exercise your workload — the sensor profiles containers while they run
#    Profiles are written to /var/lib/tracepod/profiles/<container-id>/files.json
#    on the node when the container stops

# 4. Retrieve the manifest from inside the sensor pod
kubectl exec -n tracepod daemonset/tracepod-sensor -- \
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
- If `harden build` exits 0 but the hardened image fails to start, run with `--verbose` and use `--include` to add missing directories

### Standalone (single Linux host, no Kubernetes)

The sensor can run directly on a Linux host and profile containers started via `crictl`:

```bash
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

Run `harden build -help` or `harden extract -help` for the full flag reference.

**Exit codes:**
- `0` — success
- `1` — fatal error (missing required flags, pull failed, unresolved ELF dependencies)
- `2` — non-fatal warning: a scratch-compat file (other than `resolv.conf`) was absent from the source image layers; `resolv.conf` absence is expected and exits `0`

## Confidence scoring

The hardener scores each build from 0–100 based on profiling completeness.
A short profiling window, manual entries, or no observations all reduce the score.
See [docs/CONFIDENCE.md](docs/CONFIDENCE.md) for the full breakdown.

```
Confidence:  82/100 (High) — short profiling window; startup race (4 paths)
```

## Troubleshooting

### No profiles appear after the container stops

1. **Is NRI enabled?**
   ```bash
   grep disable /etc/containerd/config.toml | grep nri
   ```
   Should print `disable = false` or be absent. Restart containerd if you change it.

2. **Is the sensor connected?**
   ```bash
   kubectl logs -n tracepod daemonset/tracepod-sensor | tail -20
   ```
   Look for `NRI connected`. If absent, the plugin failed to register — NRI is likely disabled.

3. **Was the container started via the CRI?**
   Only containers created by kubelet (Kubernetes pods) or `crictl` are profiled.
   `docker run`, `nerdctl run`, and `docker-compose` are not profiled. See
   [Known Limitations](docs/KNOWN-LIMITATIONS.md).

4. **Did the container stop?**
   Profiles are written when the container stops, not while it is running. The sensor
   aggregates events during the container's lifetime and flushes them on stop.

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

## Documentation

- [Architecture](docs/architecture.md)
- [Confidence scoring](docs/CONFIDENCE.md)
- [Known limitations](docs/KNOWN-LIMITATIONS.md)
- [Contributing](CONTRIBUTING.md)
- [Helm chart](helm/tracepod/README.md)

## Licence

AGPL-3.0 — see [LICENSE](LICENSE).
