# Profile Schema

The **profile document** is the JSON the sensor produces for one container
profiling window. In standalone mode it is written to
`profiles/<container-id>/files.json`; in DaemonSet mode it is POSTed to the
controller. Downstream tools — the hardener, the confidence scorer, and the
controller-side coverage-scoring model — consume it.

This directory holds the formal JSON Schema for each published version:

| File | Version | Status | `schema_version` value |
|------|---------|--------|------------------------|
| [`v1.schema.json`](v1.schema.json) | 1 | legacy (retained) | string `"1"` |
| [`v2.schema.json`](v2.schema.json) | 2 | legacy (retained) | integer `2` |
| [`v3.schema.json`](v3.schema.json) | 3 | **current** (revised in place 2026-06-11, see note) | integer `3` |

## Versioning policy

1. **Every profile carries a top-level `schema_version`.** As of v2 it is an
   **integer**. (v1 used the string `"1"`; see _Legacy profiles_ below.)
2. **The sensor only ever emits the current version.** There is no
   forward/backward negotiation and no in-repo migration code — nothing in this
   repository consumes profiles.
3. **Any change to the wire shape requires a version bump.** Adding, removing,
   renaming, or retyping a field, or changing the documented semantics of an
   existing field, means:
   - bump `manifest.SchemaVersion` (in `manifest/manifest.go`);
   - add a new `docs/profile-schema/v<N>.schema.json` (do **not** edit a
     published one — they are immutable);
   - record the new file's hash in `publishedSchemaHashes`
     (`manifest/schema_drift_test.go`);
   - update this table and the field reference;
   - add a CHANGELOG entry.
4. **Published schemas are frozen.** `TestSchemaDrift_publishedSchemasAreFrozen`
   fails if any `v<N>.schema.json` changes after publication, and the
   conformance test validates every assembled document against the *current*
   schema with `additionalProperties: false`. Together these make an
   un-versioned shape change fail CI: you cannot change the assembled document
   without either the conformance test or the frozen-hash test going red.

> **v3-revision note (2026-06-11, OSS-4b) — one-time exception, NOT precedent.**
> v3 was revised *in place* to add the `event_loss.tolerated` category (the openat
> path-read fault, previously documented as out-of-scope, is now a counted but
> separately-gated tolerated loss). This breaks the frozen-schema rule above
> deliberately and exactly once: it was done **before any consumer of v3 existed**
> (controller ingest of `event_loss` was unwritten at the time), so no deployed
> reader could observe the change. The drift hash in `publishedSchemaHashes` was
> regenerated accordingly. This is **not** a precedent: once anything consumes a
> published version, any shape change requires a new `v<N+1>.schema.json` and a
> `SchemaVersion` bump per the policy above — no further in-place edits to v3.

## Legacy profiles (consumer guidance)

A profile is **legacy v1** if its `schema_version` is the string `"1"`, or if the
field is absent entirely. Consumers should:

- Treat a string `schema_version` (or none) as v1 and an integer as v≥2.
- Assume v1 profiles have **no coverage information**: `process_start_observed`
  is unknown (treat as `false` / "startup coverage unverified") and there are no
  `container_starts` records (restart count unknown).
- Not attempt to upgrade v1 documents in place; re-profile under the current
  sensor to obtain a v2 document.

## v3 field reference

Top-level object:

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | integer | Always `3`. |
| `container_id` | string | Runtime container ID profiled. |
| `image_ref` | string | OCI image ref; omitted when unresolved (standalone mode). |
| `profile_start` | RFC 3339 | Aggregator creation time (first witnessed start). |
| `profile_end` | RFC 3339 | Snapshot time (container stop). |
| `coverage` | object | R2 markers; always present. |
| `container_starts` | array | R3 start records; always present (≥1 normally). |
| `event_loss` | object | **v3** — window-level event-loss counters; always present. |
| `files` | object | File entries keyed by absolute path. |

> v3 is v2 plus the `event_loss` block. **No v2 field semantics changed**; a v2
> consumer that ignores unknown fields reads a v3 document as a v2 document
> (minus the loss signal). The version still bumped because the wire shape gained
> a required field (per the versioning policy).

### `coverage` (R2 — process-start coverage marker)

| Field | Type | Notes |
|-------|------|-------|
| `process_start_observed` | boolean | See semantics below. |
| `attach_time` | RFC 3339 | When the sensor allowlisted the container's cgroup. Zero value (`0001-01-01T00:00:00Z`) means no attach was recorded. |
| `first_exec_time` | RFC 3339 | First exec observed for the container; omitted if none. |

**`process_start_observed` semantics.** "Observed from first exec" means the
sensor can demonstrate it was watching the container's cgroup *before* the
container's main process first `exec`'d — i.e. its eBPF attachment won the NRI
startup race (see [known-limitations §1](../KNOWN-LIMITATIONS.md)). It is set
`true` only when **all** of:

1. the sensor recorded an attach (`attach_time` is set);
2. the container was **not** already running when the sensor attached — the
   sensor learned of it via the NRI `StartContainer` hook (attaching before the
   runtime started the workload), rather than adopting an already-running
   container at sensor startup via NRI `Synchronize` (whose first exec was
   dropped in-kernel before the sensor attached);
3. the sensor observed at least one exec (`first_exec_time` is set); and
4. `attach_time` strictly precedes `first_exec_time`.

> **Why not probe `cgroup.procs` at attach?** At the `StartContainer` hook the
> container's pre-exec `runc-init` process is already in the cgroup even though
> the workload's entrypoint has not exec'd yet — so a `cgroup.procs` emptiness
> check would wrongly mark every fresh start as a lost race. The honest signal is
> the lifecycle hook the sensor attached through.

**Bias toward `false`.** Any uncertainty resolves to `false`: a missing attach,
an already-running process at attach, no observed exec, or non-strict ordering
all yield `false`. A wrongly-`true` marker would poison every downstream coverage
claim (the consumer would assume startup paths were captured when they were
not), so the conservative direction is deliberate. A `false` marker tells the
consumer that startup code paths are **systematically missing** from this
profile and should be scored as such — it does **not** mean the profile is
invalid, only that the startup window is unverified.

The sensor **records** these signals; it does **not** score or interpret them.

### `container_starts` (R3 — restart markers)

Array of `{ container_id, timestamp }`, in observation order — one per container
start the sensor witnessed during the window via the NRI `StartContainer` hook
(or adopted at sensor startup via `Synchronize`).

- A consumer counts **full restarts within a single profile** as
  `len(container_starts) - 1`.
- Because the sensor emits one profile per container lifecycle, the common case
  is exactly one entry (zero restarts). To count restarts of a *workload* across
  its lifetime, **sum `container_starts` across the profiles emitted for that
  workload** (the controller correlates them by namespace/deployment).
- The sensor records only starts it actually witnessed. A start it missed (a
  container already running before the sensor attached) is **not** listed here;
  that gap is surfaced instead by `coverage.process_start_observed = false` on
  the adopted container's profile.

### `event_loss` (v3 — window-level event-loss counters)

```jsonc
"event_loss": {
  "total": 0,                       // HARD losses only — the strict-zero gate
  "by_stage": {
    "bpf_reserve_failed": 0,
    "decode_failed": 0,
    "untracked_cgroup": 0
  },
  "tolerated": {                    // counted, gated by the CONSUMER, never in total
    "path_read_failed": 1
  },
  "not_instrumented": []
}
```

| Field | Type | Notes |
|-------|------|-------|
| `total` | integer ≥0 | Sum of all `by_stage` counts (**hard losses only**; excludes `tolerated`). **The strict-zero consumer gate.** |
| `by_stage` | object | Per-stage **hard**-loss counts, keyed by audited loss-point name. Their values sum to `total`. A stage present with value `0` is an explicit "counted, lost nothing". |
| `tolerated` | object | Per-stage **tolerated**-loss counts (e.g. `path_read_failed`). Counted observations lost for reasons with a known intrinsic floor — **excluded from `total`** and gated separately by the consumer. See below. |
| `not_instrumented` | array | Audited loss points (hard or tolerated) **not** counted this window (the escape hatch). Empty in the normal case. |

**Semantics a consumer must honour (verbatim):**

- `total` = Σ `by_stage` only — hard losses; the strict-zero contract is that a
  clean window reports `total: 0` and only then may "not observed ⇒ not loaded" be
  read.
- `tolerated` stages are counted observations lost for reasons with a known
  intrinsic floor; consumers **MUST** gate them with their own (conservative,
  configurable) ceiling and **MUST** surface the counts in any evidence they emit
  — never fold them into `total`, never ignore them.
- `not_instrumented` is reserved for in-scope points that could not be counted; it
  is **empty** in this sensor as of schema v3 (every audited point — hard and
  tolerated — is instrumented).

**The sensor reports; the consumer judges.** There is no score, threshold, or
interpretation in this block — only counts.

**Window-level, not per-container.** The counts cover the container's profiling
window. Buffer-level drops happen below the per-container layer (a full ring
buffer, a per-CPU kernel counter) and **cannot be attributed to one container**.
So the counters are process-wide deltas over the window, and **any nonzero
`total` taints the "not observed ⇒ not loaded" conclusion for *every* container
observed in that window** — the conservative direction. Two containers profiled
concurrently will both carry the loss seen during their overlap. This is
intentional double-attribution, not a bug: it is never wrong to *suspect* loss.

**Consumer guidance (the reason this block exists).** The coverage score's
discovery-plateau component rises when path discovery flattens — but dropped
events make a busy window *look* flat, so the score can rise exactly when
observation quality fell. Therefore:

- **Hard losses (`total` / `by_stage`): gate at zero.** Treat any nonzero
  `event_loss.total` as grounds to withhold "not observed ⇒ not loaded"
  conclusions for the whole window — i.e. do not promote files/containers in that
  window to "not affected" on the strength of *absence* of observation. Use
  `by_stage` only to diagnose *where* the loss happened. This mirrors the
  missed-start floor: above a loss threshold, no `not_affected` promotion.
- **Tolerated losses (`tolerated`): gate at a configurable ceiling, never at
  zero.** These have a known nonzero intrinsic floor, so a strict-zero gate would
  fire on every window and is wrong. Set a conservative, **configurable** ceiling
  (see the suggested default below) and withhold "not loaded" conclusions only
  when a tolerated count exceeds it. Crucially, do **not** treat tolerated losses
  as free: each is a file open that went unidentified. **Always print the
  tolerated counts in any evidence/report you emit**, even when below the ceiling,
  so a reviewer sees that some observations were lost — `total: 0` with a nonzero
  `tolerated.path_read_failed` means "no hard loss, but N opens went
  unidentified", not "nothing lost".

> **Suggested default ceiling for `path_read_failed`.** Measured behaviour: the
> idle floor is **0–2** per container-window; a memory-pressure probe (free RAM
> driven to ~80 MB under `stress-ng --vm`) did **not** move it off the floor — the
> openat filename string is small and hot, not the kind of page anonymous memory
> pressure evicts. The only condition that drove it large (~10⁴) was an extreme
> ring-buffer-starvation storm, where `total` (hard losses) is already firing. So a
> **dual, configurable** gate is recommended, defaulting to: trip when
> `path_read_failed > 16` (8× the floor) **and/or** when
> `path_read_failed / Σ files[].count > 0.01` (1% of observed opens). The fraction
> guard matters because the fault tracks total open *volume*, not memory footprint,
> so an absolute-only ceiling would false-fire on high-throughput workloads. The
> sensor reports the data; the consumer owns the threshold and must keep it
> configurable.

**Zero is a claim.** `total: 0` means "instrumented at every audited **hard** loss
point and nothing was lost there" — it never means "we didn't count." Every stage
the sensor instruments appears in `by_stage` / `tolerated` (at `0` if clean). A
loss point that *could not* be instrumented for a window (e.g. a runtime failure
reading the in-kernel counter) is named in `not_instrumented` and **omitted** from
`by_stage`/`tolerated`, so it can never masquerade as a zero. A consumer seeing a
non-empty `not_instrumented` should treat those stages as *unknown*, not *clean*.

#### Loss-point audit (the stages)

Every point on the path from the BPF programs to the assembled profile where an
event can be dropped, and how each is counted:

| Stage | Class | Where | Counted | What it means |
|-------|-------|-------|---------|---------------|
| `bpf_reserve_failed` | hard (`total`) | BPF programs (all 3 kprobes) | in-kernel per-CPU map | `bpf_ringbuf_reserve()` returned `NULL` — the ring was full because userspace was not draining fast enough. **The primary buffer-pressure loss point.** |
| `decode_failed` | hard (`total`) | userspace ring-buffer consumer | userspace atomic | a committed record was too short/malformed to decode into an event and was skipped. |
| `untracked_cgroup` | hard (`total`) | userspace router | userspace atomic | the kernel emitted an event for an allowed cgroup that arrived with no live aggregator — the brief race between the BPF allowlist and the userspace aggregator map at container start/stop. |
| `path_read_failed` | **tolerated** | openat BPF kprobe | in-kernel per-CPU map | `bpf_probe_read_user_str()` faulted on the userspace filename pointer (e.g. the page is not yet present): the reservation succeeded but the path was unreadable, so the open went **unidentified**. See below. |

The BPF-side stages **must** be counted in the kernel (a per-CPU array, read at
profile finalisation): userspace never sees a reservation that never happened, nor
a discard the kernel performed, so a userspace counter there would silently read
zero — a false zero. The counters are themselves loss-proof: an in-kernel per-CPU
array increment cannot be dropped, and the userspace counters are atomic.

**Tolerated category — `path_read_failed`.** The openat kprobe discards an event
when `bpf_probe_read_user_str()` faults on the userspace filename pointer (e.g.
the page is not yet present): the reservation succeeded but the path was
unreadable, so the open goes **unidentified** — a real lost observation. It is
counted (a consumer must not be told `total: 0` and conclude "nothing lost" while
file opens went unidentified). But it is a *path-read fault*, a different class
from the capacity/transport drops above, with a **load-independent nonzero floor**
— 0–2 per container even at idle. Folding it into `total` would put a permanent
floor under the strict-zero gate on hard losses (every window would look lossy)
and defeat it; the dominant, load-correlated loss (`bpf_reserve_failed`) is fully
counted under `total` — under the induced-loss storm reserve failures outnumber
read faults by ~100:1. It therefore lives in `tolerated`, **visible but separately
gated by the consumer** (gate at a configurable ceiling, never zero; always
surface the count). It is *not* placed in `not_instrumented`: as of schema v3 it
**is** instrumented. (Whether the floor stays bounded under memory pressure is the
open question the consumer's ceiling must be configured for — see the recorded
memory-pressure data.)

**No `reader` stage.** The sensor uses a BPF **ring buffer** (`BPF_MAP_TYPE_RINGBUF`),
not a perf buffer. The `cilium/ebpf` ring-buffer reader has no lost-sample
concept — it reads every committed record. Backpressure (a slow reader) surfaces
in the kernel as a `bpf_reserve_failed`, already counted; there is nothing to
count at the reader, so there is no `reader_lost` stage (it is not omitted as
`not_instrumented` — it is structurally not a loss point here). Were the sensor
ever switched to a perf buffer, the reader's `LostSamples` would become a stage.

### `files` (file entries)

Keyed by absolute path. Each entry:

| Field | Type | Notes |
|-------|------|-------|
| `source` | enum | `direct` \| `inferred-elf` \| `directory-inclusion` \| `manual` \| `ensure-dir` \| `ensure-file`. Load-bearing for confidence scoring; never flattened. |
| `access_modes` | array | Subset of `r w x l m` (read/write/execute/link/mmap-PROT_EXEC). |
| `first_seen` / `last_seen` | RFC 3339 | See timestamp semantics. |
| `count` | integer ≥0 | Observed opens; `0` for `inferred-elf` / `directory-inclusion`. |
| `inferred_from` | string | `source=inferred-elf`: the ELF that required this `.so`. |
| `included_because` | string | `source=directory-inclusion`/`manual`: inclusion reason. |

> **Build-time sources beyond the published enum.** The hardener's runtime
> companion resolver adds entries with `source: "inferred-runtime"` (e.g. a
> CPython `__pycache__` pyc implies its sibling `.py`, which the interpreter
> stats but never opens; `inferred_from` names the triggering pyc). The sensor
> never emits this source, so the published **profile** schema above is
> unchanged — it appears only in build-time manifests produced by the
> hardener. It joins the published enum at the next schema version (v4);
> until then, validators of hardener output should accept it explicitly.

### Timestamp semantics (R4)

All timestamps (`profile_start`/`end`, `coverage.attach_time`/`first_exec_time`,
each `container_starts[].timestamp`, and every `files.*.first_seen`/`last_seen`)
are **UTC RFC 3339 with nanosecond resolution** — well above the
at-least-second resolution a consumer needs to bucket events into intervals for
first-seen-unique-path curves.

They are sourced from the **sensor host's wall clock** (`time.Now()`) at
event-processing time. They are therefore **not guaranteed strictly monotonic**
across events: a wall-clock adjustment (NTP step) can move them backwards by a
small amount. Consumers computing time-bucketed curves should bucket at second
resolution or coarser and tolerate small non-monotonicities; they must not
assume `first_seen` values form a strictly increasing sequence in event order.
