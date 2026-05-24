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
| `tracepod` | Linux + macOS | CLI client for the controller API |

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
CGO_ENABLED=0 go build ./cmd/tracepod/
# sensor requires Linux + BPF toolchain — see CONTRIBUTING.md
```

## Quick start (harden CLI)

```bash
# 1. Start profiling a running container (sensor must be running)
#    Profile is posted automatically at container stop

# 2. Retrieve the manifest and build a hardened image
harden build \
  --manifest manifest.json \
  --source nginx:1.25-alpine \
  --output /tmp/hardened-nginx

# 3. Import and test the hardened image
docker load -i /tmp/hardened-nginx/oci-layout
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)

## Licence

AGPL-3.0 — see [LICENSE](LICENSE).
