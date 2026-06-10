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
| [`v2.schema.json`](v2.schema.json) | 2 | **current** | integer `2` |

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

## Legacy profiles (consumer guidance)

A profile is **legacy v1** if its `schema_version` is the string `"1"`, or if the
field is absent entirely. Consumers should:

- Treat a string `schema_version` (or none) as v1 and an integer as v≥2.
- Assume v1 profiles have **no coverage information**: `process_start_observed`
  is unknown (treat as `false` / "startup coverage unverified") and there are no
  `container_starts` records (restart count unknown).
- Not attempt to upgrade v1 documents in place; re-profile under the current
  sensor to obtain a v2 document.

## v2 field reference

Top-level object:

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | integer | Always `2`. |
| `container_id` | string | Runtime container ID profiled. |
| `image_ref` | string | OCI image ref; omitted when unresolved (standalone mode). |
| `profile_start` | RFC 3339 | Aggregator creation time (first witnessed start). |
| `profile_end` | RFC 3339 | Snapshot time (container stop). |
| `coverage` | object | R2 markers; always present. |
| `container_starts` | array | R3 start records; always present (≥1 normally). |
| `files` | object | File entries keyed by absolute path. |

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
