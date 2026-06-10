# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/tracepod/tracepod/compare/v0.1.0...HEAD
