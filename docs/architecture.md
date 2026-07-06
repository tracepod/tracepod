# Architecture

## Overview

Tracepod has three components that form a pipeline:

```
┌──────────────────────────────────────────────────────────────┐
│  Kubernetes node                                              │
│                                                              │
│  ┌──────────────┐  eBPF kprobes    ┌──────────────────────┐ │
│  │  Container   │─(openat/execve/─►│   eBPF sensor        │ │
│  │  (nginx etc) │   mmap)          │   (DaemonSet pod)    │ │
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

The sensor attaches three kprobes using [cilium/ebpf](https://github.com/cilium/ebpf)
with CO-RE (Compile Once, Run Everywhere) BPF objects. Events flow through a ring buffer
to the userspace consumer.

Each event is filtered by cgroup namespace inode — only events from the target container
reach userspace. The sensor uses the containerd NRI (`StopContainer` hook) to learn when a
container stops and submit the complete manifest.

The three kprobes are:

- **`kprobe/do_sys_openat2`** — fires on every file open. The raw user-space path string is
  captured. Absolute paths are passed through directly; relative paths (e.g. `app.rb` opened
  via `openat(AT_FDCWD, ...)`) are resolved to absolute paths in userspace via CWD resolution
  (see below).
- **`kprobe/security_bprm_check`** — fires after `prepare_binprm()` has fully populated
  `linux_binprm`. Captures both the binary path and the shebang interpreter path (e.g.
  `/usr/bin/python3` for a `#!/usr/bin/python3` script). For native ELF binaries, both
  fields are identical.
- **`kprobe/security_mmap_file`** — fires on every file-backed `mmap(2)` with `PROT_EXEC`.
  Captures the basename only (e.g. `libc.so.6`) because `bpf_d_path` is unavailable in
  kprobe context. The userspace handler correlates the basename against full paths already
  recorded by the openat probe — the dynamic linker always opens a file before mapping it.

### CWD-relative path resolution

`bpf_get_current_pid_tgid()` returns PIDs in the kernel's outermost PID namespace. In
production Kubernetes the sensor's `/proc` uses that same namespace, so resolving
`/proc/<bpf_pid>/cwd` works directly.

In nested environments (e.g. kind-in-Lima VM), the sensor's `/proc` shows kind-node PIDs
while BPF reports Lima VM PIDs. When the direct readlink fails, the fallback reads
`<cgroupFSPath>/cgroup.procs` to obtain a locally-visible PID, then reads its `/proc` cwd
entry. The cgroupfs path is supplied by the NRI `onStart` callback.

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
| `inferred-runtime` | Language-runtime companion rule (e.g. a CPython `__pycache__` pyc implies its sibling `.py` source, which the interpreter stats but never opens) |
| `directory-inclusion` | Safe-mode directory expansion |
| `manual` | Added explicitly via `--include` flag |

This distinction is what makes confidence scoring and audit trails possible.

## Hardener

The hardener (`hardener/builder.go`) takes a manifest and a source OCI image and
produces a new minimal image:

1. **Pull** the source image via `google/go-containerregistry`
2. **Resolve ELF dependencies** — walk each `direct` binary's shared library requirements
   recursively via `readelf` + `ld.so.conf` parsing
3. **Build a single deterministic layer** — sorted paths, zero mtime, scratch base
4. **Preserve the original config** — `Entrypoint`, `Cmd`, `Env`, `User`, `WorkingDir`,
   `ExposedPorts`, `Healthcheck`; add `com.tracepod.*` provenance labels
5. **Write OCI layout** to disk; optionally push via crane

## ELF dependency resolver

The ELF resolver (`hardener/elf.go`) is the #1 correctness risk in the pipeline.
It must handle `RPATH`, `RUNPATH`, `LD_LIBRARY_PATH`, `/etc/ld.so.conf.d/` includes, and
`dlopen()` patterns. Missing a dependency causes the hardened image to crash at runtime.

## Confidence scoring

Each manifest gets a confidence score (0–100) based on:

- Profiling window length
- Ratio of `direct` to `inferred-elf` observations
- Presence of cold-start paths
- Number of distinct observation events

See `manifest/confidence.go` for the scoring model.
