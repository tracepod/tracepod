# Architecture

## Overview

Tracepod has three components that form a pipeline:

```
┌──────────────────────────────────────────────────────────────┐
│  Kubernetes node                                              │
│                                                              │
│  ┌──────────────┐   kprobe on      ┌──────────────────────┐ │
│  │  Container   │──── openat() ───►│   eBPF sensor        │ │
│  │  (nginx etc) │                  │   (DaemonSet pod)    │ │
│  └──────────────┘                  └──────────┬───────────┘ │
│                                               │              │
│                                      file manifest (JSON)    │
└──────────────────────────────────────────────┼───────────────┘
                                               │
                                               ▼
                                     ┌──────────────────┐
                                     │   harden CLI     │
                                     │                  │
                                     │  1. Pull source  │
                                     │  2. Resolve ELF  │
                                     │  3. Build layer  │
                                     │  4. Write OCI    │
                                     └──────────────────┘
```

## eBPF sensor

The sensor attaches a kprobe to the `openat()` syscall using [cilium/ebpf](https://github.com/cilium/ebpf)
with CO-RE (Compile Once, Run Everywhere) BPF objects. Events flow through a ring buffer
to the userspace consumer.

Each event is filtered by cgroup namespace inode — only file opens from the target container
reach userspace. The sensor uses the containerd NRI (`StopContainer` hook) to learn when a
container stops and submit the complete manifest.

## Manifest

The manifest is the core data structure:

```json
{
  "files": {
    "/usr/sbin/nginx": {
      "source":          "direct",
      "first_seen":      "2026-01-01T00:00:00Z",
      "last_seen":       "2026-01-01T01:00:00Z",
      "count":           42
    },
    "/lib/libssl.so.3": {
      "source":          "inferred-elf",
      ...
    }
  }
}
```

Each file carries an `observation_source` that records how it was discovered:

| Source | Meaning |
|--------|---------|
| `direct` | Observed by eBPF kprobe |
| `inferred-elf` | ELF shared library dependency resolved from a `direct` binary |
| `directory-inclusion` | Safe-mode directory expansion |
| `manual` | Added explicitly via `--include` flag |

This distinction is what makes confidence scoring and audit trails possible.

## Hardener

The hardener (`internal/hardener/builder.go`) takes a manifest and a source OCI image and
produces a new minimal image:

1. **Pull** the source image via `google/go-containerregistry`
2. **Resolve ELF dependencies** — walk each `direct` binary's shared library requirements
   recursively via `readelf` + `ld.so.conf` parsing
3. **Build a single deterministic layer** — sorted paths, zero mtime, scratch base
4. **Preserve the original config** — `Entrypoint`, `Cmd`, `Env`, `User`, `WorkingDir`,
   `ExposedPorts`, `Healthcheck`; add `com.tracepod.*` provenance labels
5. **Write OCI layout** to disk; optionally push via crane

## ELF dependency resolver

The ELF resolver (`internal/hardener/elf.go`) is the #1 correctness risk in the pipeline.
It must handle `RPATH`, `RUNPATH`, `LD_LIBRARY_PATH`, `/etc/ld.so.conf.d/` includes, and
`dlopen()` patterns. Missing a dependency causes the hardened image to crash at runtime.

## Confidence scoring

Each manifest gets a confidence score (0–100) based on:

- Profiling window length
- Ratio of `direct` to `inferred-elf` observations
- Presence of cold-start paths
- Number of distinct observation events

See `internal/manifest/confidence.go` for the scoring model.
