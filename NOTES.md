# NOTES — OSS-1: Sensor Coverage Markers & Profile Schema Versioning

Working branch: `feat/profile-schema-v2-coverage-markers`

## Status

| Req | State |
|-----|-------|
| R1 schema version (int 2) + JSON Schema files | ✅ done, tested |
| R2 process-start marker | ✅ done, tested (unit + sensor wiring) |
| R3 container_starts records | ✅ done, tested |
| R4 timestamp resolution/monotonicity (documented) | ✅ done (already present; semantics documented) |
| R5 backward-compat / legacy guidance | ✅ done (schema README) |
| R6 recorded fixtures | ✅ recorded in Lima k8s-dev: static/interp/restart×3/missed-start, schema-validated |
| Conformance + R2/R3 unit tests | ✅ done, green |
| Schema-drift guard | ✅ done (frozen-hash + conformance) |
| Fixture workflow_dispatch | ✅ done |
| Docs (schema README, known-limitations, CHANGELOG) | ✅ done |

## Audit (pre-change profile shape)

- `Manifest` already had: `schema_version` (was **string "1"**), `container_id`,
  `image_ref`, `profile_start/end`, `files{}` with per-file `source`,
  `access_modes`, `first_seen`, `last_seen`, `count`, `inferred_from`,
  `included_because`.
- R4 (timestamps) was **already satisfied**: every file entry carries
  RFC3339-nanosecond first/last seen. We only documented resolution + the
  non-monotonic (wall-clock) caveat.
- Missing before this work: integer version, coverage marker (R2), start
  records (R3), formal JSON Schema, conformance/drift CI.

## Key decisions

- `schema_version` string "1" → **integer 2**. `manifest.SchemaVersion` const.
- **R2 honest signal = NRI hook type (empirically validated).** Initial attempt
  used a `cgroup.procs`-emptiness probe at attach, but the Lima fixtures proved
  it wrong: at the `StartContainer` hook the pre-exec `runc-init` is already in
  the cgroup, so that probe marked EVERY fresh start as a lost race (all
  fixtures false — useless). Correct discriminator: HOW the sensor learned of the
  container. `StartContainer` hook ⇒ attached before the runtime started the
  workload ⇒ race won (alreadyRunning=false). `Synchronize` (adopting an
  already-running container at sensor start) ⇒ race lost (alreadyRunning=true).
  Marker true only when: StartContainer-attached, an exec observed, and attach
  strictly before the first observed exec. All uncertainty → false. Fixtures
  confirm: live workloads true (attach ~2ms before first exec), missed-start
  (deployed before sensor) false.
- **NRI `Synchronize` added**: already-running containers at sensor start are
  adopted (so they produce a profile) and always marked
  `process_start_observed:false` — this is the R2 missed-start case.
- **R3**: one profile per container lifecycle ⇒ normally one start record. A
  consumer counts restarts within a profile as len-1 and sums across a
  workload's profiles for cross-window totals. `RecordStart` supports in-place
  restart appends. Documented in schema README.
- **Drift guard** = conformance test (assembled doc must validate vs current
  schema, `additionalProperties:false`) + frozen per-version schema hashes in
  `manifest/schema_drift_test.go`. Shape change ⇒ conformance breaks ⇒ editing
  the frozen schema breaks the hash ⇒ forces a new vN file + SchemaVersion bump.

## Files touched

- `manifest/manifest.go` — SchemaVersion const, Coverage, StartEvent, Manifest v2.
- `manifest/aggregator.go` — RecordAttach, RecordStart, first-exec tracking,
  Snapshot builds Coverage + ContainerStarts, processStartObservedLocked.
- `internal/container/nri.go` — StartInfo, adopt(), cgroupHasProcs, Synchronize.
- `cmd/sensor/main.go` — onContainerStart consumes StartInfo + RecordAttach.
- `manifest/schema_test.go`, `coverage_test.go`, `schema_drift_test.go` — tests.
- `docs/profile-schema/{v1,v2}.schema.json`, `README.md`; `docs/KNOWN-LIMITATIONS.md`.
- `hack/record-profile-fixtures.sh`, `hack/schemaversion/main.go`, Makefile target.
- `.github/workflows/record-fixtures.yaml`; `hack/e2e/run-e2e.sh` (v2 assertions).
- `CHANGELOG.md`, `testdata/profile-fixtures/README.md`.
- Dep added: `github.com/santhosh-tekuri/jsonschema/v6` (pure Go, CGO-free).

## Verification (all green)

- `go test ./...` in the k8s-dev Lima VM (incl. BPF packages): PASS.
- macOS `go test` (non-BPF) + `go vet` (darwin) + linux sensor build: PASS.
- e2e in Lima (`hack/e2e/run-e2e.sh`): PASS — Phase 5b asserts schema_version=2,
  `process_start_observed=true` for sensor-first nginx, `container_starts>=1`;
  hardened nginx `nginx -t` validated. (Fixed a latent e2e bug: stale root-owned
  profiles in the persistent host PROFILE_DIR were picked up by `find|head -1`;
  the script now `sudo rm -rf`s the dir at start.)
- Fixtures recorded in Lima and committed: static (true), interp (true, 135
  files), restart ×3 generations (true), missed-start (false). All validate
  against v2 schema; `TestProfileFixtures_{conform,coverScenarios}` enforce it.

## Verify locally

```
go test ./...                 # manifest conformance + R2/R3 + drift all green
go run ./hack/schemaversion   # prints 2
make record-fixtures          # records into testdata/profile-fixtures/v2/ (needs Lima)
```
