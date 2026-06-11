# NOTES — OSS-4: Sensor Event-Loss Counters (Profile Schema v3)

Working branch: `feat/profile-schema-v3-event-loss`
Builds on OSS-1 (schema v2 coverage markers). v3 = v2 + a top-level `event_loss`
block; no v2 field semantics changed.

## Status

| Req | State |
|-----|-------|
| R1 count at every audited loss point (loss-proof counters) | ✅ done |
| R2 schema v3 `event_loss{total, by_stage, not_instrumented}`, window-level | ✅ done |
| R3 zero-is-a-claim / `not_instrumented` escape hatch | ✅ done, tested |
| R4 schema policy: integer v3, new schema file, v1/v2 retained, drift hashes | ✅ done |
| R5 fixtures re-recorded under v3 + induced-loss scenario | ✅ recorded in Lima kind |
| Unit tests (accumulation, sum invariant, zero-claim) | ✅ green |
| BPF-side test (per-CPU counter map present/readable/summed) | ✅ green (VM, root) |
| e2e (Lima) v3 + true-zero assertions | ✅ assertions added to run-e2e.sh |
| Docs (schema README, known-limitations, CHANGELOG, fixtures README) | ✅ done |

## Loss-point audit (the deliverable's core)

Event path: BPF kprobes → ringbuf map → cilium/ebpf RINGBUF reader →
ringbuf.Consumer (binary decode) → router.handle → aggregator. Every drop point:

| Stage | Where | Counted (loss-proof) | Note |
|-------|-------|----------------------|------|
| `bpf_reserve_failed` | all 3 kprobes | in-kernel per-CPU array (`event_loss_stats[0]`) | `bpf_ringbuf_reserve()`==NULL. **Primary buffer-pressure point.** Userspace can't see it → MUST be in-kernel. |
| `bpf_read_failed` | openat kprobe | in-kernel per-CPU array (`event_loss_stats[1]`) | `bpf_probe_read_user_str()` fault → reserved-but-discarded. |
| `decode_failed` | ringbuf.Consumer | userspace atomic | malformed/short record skipped. |
| `untracked_cgroup` | router.handle | userspace atomic | event for an allowed cgroup with no live aggregator (start/stop race). |

**Not a loss point:** the cilium/ebpf RINGBUF reader. Ring buffers have no
lost-sample concept (unlike perf buffers) — the reader reads every committed
record; backpressure surfaces in-kernel as `bpf_reserve_failed`. So there is **no
`reader_lost` stage** — it is structurally absent, not `not_instrumented`.
Documented in docs/profile-schema/README.md.

## Design: window-level counters via baseline delta

- The counters are **process-wide and monotonic** (per-CPU BPF map summed +
  userspace atomics). They are NOT per-container — buffer drops aren't
  attributable to one container (R2).
- `manifest.Aggregator.SetLossReader(r)` captures a **baseline** read at window
  start; `Snapshot()` emits `current − baseline` per stage. Concurrent windows
  both see shared losses → conservative double-attribution (intended).
- `cmd/sensor.cgroupRouter` implements `manifest.LossReader.ReadLoss()`: sums
  `probe.LossStats()` (BPF) + `consumer.DecodeFailures()` + its own
  `untrackedCgroup` atomic. On BPF-read error those stages go to
  `not_instrumented` (never a false zero).
- nil reader (synthetic aggregators in unit tests) ⇒ every stage
  `not_instrumented`, `total 0`, `by_stage {}` — honest "did not count".

## Key files touched

- `manifest/eventloss.go` — NEW: stage consts, `LossStages`, `EventLoss`,
  `LossReport`, `LossReader`, the full audit as package doc.
- `manifest/manifest.go` — `SchemaVersion = 3`, `Manifest.EventLoss`.
- `manifest/aggregator.go` — `lossReader`/`lossBaseline`, `SetLossReader`,
  `eventLossLocked`, wired into `Snapshot`.
- `internal/probe/openat.c` — `event_loss_stats` PERCPU_ARRAY + `stat_inc` +
  increments at 3 reserve sites and 1 read-fail site. **Regenerated arm64 .o/.go
  via `make generate` (clang-18) in the Lima VM.**
- `internal/probe/probe.go` — `Options{RingbufBytes}`, `OpenWith`, `LossStats()`.
- `internal/probe/loss_test.go` — NEW: BPF-side per-CPU map smoke + sum tests.
- `internal/ringbuf/consumer.go` — atomic `decodeFailures` + `DecodeFailures()`.
- `cmd/sensor/main.go` — router implements LossReader; `--ringbuf-bytes`;
  `untracked_cgroup` guard in `handle`; consumer wired before plugin.Start;
  `SetLossReader` at container start.
- `internal/container/nri.go` — `adopt()` now registers aggregator (onStart)
  **before** AllowCgroup, closing the start race that would log spurious
  `untracked_cgroup`.
- `docs/profile-schema/v3.schema.json` — NEW; `manifest/schema_drift_test.go`
  hash; `docs/profile-schema/README.md` v3 reference + audit + consumer guidance.
- `docs/KNOWN-LIMITATIONS.md` §4 (event loss now machine-visible).
- `helm/.../daemonset.yaml` + `values.yaml` — `sensor.ringbufBytes` (test-only).
- `hack/record-profile-fixtures.sh` — Phase 5 induced-loss scenario.
- `hack/e2e/run-e2e.sh` — Phase 5b v3 + true-zero event_loss assertions.
- `.github/workflows/record-fixtures.yaml` — validate event-loss test.
- `CHANGELOG.md`, `testdata/profile-fixtures/README.md`.

## Verification

- macOS `go test ./manifest/... ./internal/ringbuf/...`: PASS.
- macOS `GOOS=darwin go vet ./...` + darwin/linux `CGO_ENABLED=0` builds: PASS.
- Lima VM `go test ./...` incl. `internal/probe` (root, BPF load): PASS.
- Fixtures recorded in Lima kind under `testdata/profile-fixtures/v3/` incl.
  `induced-loss.json` (`event_loss.total > 0`); all others `total: 0`. Validated
  by `TestProfileFixtures_{conform,coverScenarios,eventLoss}`.

## Verify locally

```
go test ./...
go run ./hack/schemaversion           # prints 3
make record-fixtures                  # needs Lima k8s-dev; records v3 incl induced-loss
jq '.schema_version, .event_loss' testdata/profile-fixtures/v3/*.json
```

## Gotcha log

- The record script skips the docker build if `tracepod-sensor:fixtures` already
  exists → first re-record reused a STALE v2 image (all fixtures came out v2).
  Fix: `docker rmi -f tracepod-sensor:fixtures` before re-recording after code
  changes. (The CI workflow always builds fresh, so this only bites locally.)
- The k8s-dev Lima VM did not ship clang/libbpf; installed with
  `apt-get install -y clang-18 llvm-18 libbpf-dev` (same as the CI workflow) to
  run `make generate`. clang lives under `/usr/lib/llvm-18/bin` — add to PATH.
