# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

## [0.1.2] - 2026-06-16

### Added

- **Removal manifest** (OSS-3) — every successful `harden build` now writes
  `removal-manifest.json` into the OCI output directory, alongside the SBOMs and
  travelling through the same handoff channel. It is the machine-readable
  removed-set the controller consumes to emit `component_not_present` removal-VEX
  for the hardened image without ever re-scanning it:
  - Lists every OS package present in the **source** image and **entirely absent**
    from the hardened image (`purl` + version), with the source-image file paths
    that drove each removal. A package with **any** retained file is **omitted** —
    partial retention is not removal. Multi-owner files keep all their owners.
  - **Facts only**: a set-difference, with no reachability, runtime,
    justification, or VEX vocabulary, and **no CVE/findings source** — CVE
    association stays the controller's concern.
  - Derived by scanning the already-extracted, digest-pinned source staging tree
    with `syft` (package→owned-files), then set-differencing against the finalised
    hardened file set. Same source artifact as the build consumed — no re-pull.
  - Emitted **unconditionally** on success (not behind `--sbom` or any flag);
    a missing `syft` is a non-fatal warning. Carries additive `source_platform`
    and `tooling` (hardener + syft versions) audit metadata the consumer ignores.
- `v1.schema.json` (current) under `docs/removal-manifest-schema/`, with a
  README field reference + versioning policy, and a schema-drift guard +
  conformance tests mirroring the profile-schema pattern. The e2e harden flow now
  walks both images and asserts each listed package has zero files in the hardened
  image and at least one in the source.
- **Profile schema v3** with sensor event-loss counters. The sensor now emits
  `schema_version: 3` (integer) and the profile document gains a top-level
  `event_loss` block so a downstream consumer can refuse "not observed ⇒ not
  loaded" claims from a lossy observation window:
  - `event_loss.total` — the consumer gate; any nonzero value means the window
    dropped events and "absence of observation" must not be read as "not loaded"
    for any container in the window.
  - `event_loss.by_stage` — per-stage counts keyed by audited loss point:
    `bpf_reserve_failed` (ring buffer full — the primary buffer-pressure cause,
    counted in-kernel in a per-CPU map), `decode_failed` (malformed record,
    userspace), and `untracked_cgroup` (container start/stop race, userspace). A
    fourth point, the openat path-read fault, is documented in the loss-point
    audit as deliberately out of scope (a load-independent floor that would
    defeat the gate).
  - `event_loss.not_instrumented` — the zero-is-a-claim escape hatch: a drop
    point that could not be counted is named here and omitted from `by_stage`, so
    `total: 0` always means "instrumented everywhere and lost nothing", never
    "didn't count".
  - Counts are **window-level, not per-container** — buffer drops are not
    attributable to one container, so any loss in a window taints every container
    observed in it (conservative direction).
- `v3.schema.json` (current) under `docs/profile-schema/`; `v1`/`v2` retained and
  frozen. Schema-drift guard and conformance tests extended to v3.
- A test-only `--ringbuf-bytes` sensor flag (and `sensor.ringbufBytes` Helm
  value) that shrinks the BPF events ring buffer, used by the new induced-loss
  fixture scenario to drive `event_loss.total > 0` under a real high-churn run.
- `event_loss.tolerated` — a new separately-gated loss category carrying
  `path_read_failed`, the openat `bpf_probe_read_user_str()` fault (the filename
  pointer was unreadable, so the file open went unidentified). It is counted with
  the same loss-proof in-kernel per-CPU mechanism as the hard stages but is
  **excluded from `total`**: it has a load-independent idle floor (0–2 per
  container) that would otherwise defeat the strict-zero gate on hard losses.
  Consumers gate it with their own configurable ceiling (never zero) and must
  surface the count. This supersedes the OSS-4 decision to exclude the fault from
  loss accounting entirely — "`total: 0`, nothing reported" wrongly read as
  "nothing lost" while opens went unidentified.

### Changed

- `schema_version` is now the integer `3` (was `2`). No v2 field semantics
  changed; v3 is v2 plus the additive `event_loss` block. A consumer that ignores
  unknown fields reads a v3 document as a v2 document minus the loss signal.
- **`v3.schema.json` was revised in place (2026-06-11)** to add the
  `event_loss.tolerated` object, and its schema-drift hash regenerated. This is a
  one-time exception to the frozen-schema rule, permitted only because no consumer
  of v3 existed yet; it is not a precedent (see the v3-revision note in
  `docs/profile-schema/README.md`).
- NRI container adoption now registers the userspace aggregator **before**
  allowlisting the cgroup, closing the container-start race that would otherwise
  record spurious `untracked_cgroup` event loss on every clean start.

### Fixed

- **StopContainer generation loss (OSS-5).** The sensor previously resolved a
  container's owning workload (Pod → ReplicaSet → Deployment, three live
  Kubernetes GETs) **at stop time** to decide where to POST its final profile.
  StopContainer fires during pod delete / scale-to-0 / rolling update — exactly
  when the pod and its ReplicaSet are being garbage-collected — so a 404 on that
  lookup silently dropped the entire final generation before it was ever sent
  (no retry, no cache). For a single-generation workload that is the whole
  profile, producing a merged profile silently short of what was observed. The
  owning workload is now resolved **and cached at container start**, when the pod
  and ReplicaSet reliably exist; the stop path POSTs from that cache with no live
  Kubernetes dependency. A best-effort live lookup remains only as a fallback when
  start-time resolution did not complete.
- **In-flight profiles are now flushed on `SIGTERM`/`SIGINT`.** A sensor restart,
  rollout, or node drain previously dropped the accumulated generation of every
  currently-tracked container (the signal handler only closed the ring buffer).
  The sensor now snapshots and POSTs/writes every in-flight container before exit.
  The residual `SIGKILL`-with-no-graceful-stop window is documented in
  `docs/KNOWN-LIMITATIONS.md` §5 and such profiles must be treated as truncated.

## [0.1.1] - 2026-06-10

### Added

- **Profile schema v2** with sensor coverage markers for downstream coverage
  scoring. The sensor now emits `schema_version: 2` (integer) and the profile
  document gains:
  - `coverage.process_start_observed` (R2) — whether the sensor observed the
    container's main process from its first exec (i.e. its eBPF attachment won
    the NRI startup race). Resolves all uncertainty toward `false`. Surfaces the
    long-documented startup race as a machine-detectable signal.
  - `coverage.attach_time` / `coverage.first_exec_time` — the raw signals behind
    the marker.
  - `container_starts` (R3) — start-event records (container ID + timestamp) for
    each container start the sensor witnessed, so a consumer can count restarts.
- Formal JSON Schema files under `docs/profile-schema/` (`v1.schema.json` legacy,
  `v2.schema.json` current) plus `docs/profile-schema/README.md` documenting the
  versioning policy, the R2/R3 field semantics, and legacy-profile guidance.
- NRI `Synchronize` support: containers already running when the sensor starts
  are adopted and profiled, marked `process_start_observed: false` (the
  missed-start case).
- Schema-conformance tests (every assembled profile validates against the
  committed schema) and a schema-drift guard (published schemas are frozen by
  hash; a shape change without a version bump fails CI).
- `hack/record-profile-fixtures.sh` + `make record-fixtures` and a
  `workflow_dispatch` GitHub Actions workflow that re-records
  `testdata/profile-fixtures/` and opens a PR.

### Changed

- `schema_version` changed type from string (`"1"`) to integer (`2`). Consumers
  must treat a string `schema_version` (or its absence) as a legacy v1 profile.

[Unreleased]: https://github.com/tracepod/tracepod/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/tracepod/tracepod/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tracepod/tracepod/compare/v0.1.0...v0.1.1
