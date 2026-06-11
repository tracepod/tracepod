# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

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

### Changed

- `schema_version` is now the integer `3` (was `2`). No v2 field semantics
  changed; v3 is v2 plus the additive `event_loss` block. A consumer that ignores
  unknown fields reads a v3 document as a v2 document minus the loss signal.
- NRI container adoption now registers the userspace aggregator **before**
  allowlisting the cgroup, closing the container-start race that would otherwise
  record spurious `untracked_cgroup` event loss on every clean start.

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

[Unreleased]: https://github.com/tracepod/tracepod/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/tracepod/tracepod/compare/v0.1.0...v0.1.1
