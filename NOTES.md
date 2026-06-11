# NOTES — OSS-4: Sensor Event-Loss Counters (Profile Schema v3)

Working branch: `feat/profile-schema-v3-event-loss`
Builds on OSS-1 (schema v2 coverage markers). v3 = v2 + a top-level `event_loss`
block; no v2 field semantics changed.

---

## OSS-4b amendment — Tolerated-Loss Category (path_read_failed)

Supersedes OSS-4's decision to *exclude* the openat path-read fault from loss
accounting. It is now COUNTED and visible as a separately-gated `tolerated`
category — hard losses keep the strict-zero contract exactly as before.

### What changed

| Req | State |
|-----|-------|
| R1 count the fault (loss-proof per-CPU, new key STAT_PATH_READ_FAILED) | ✅ |
| R2 schema shape `event_loss{total, by_stage, tolerated{path_read_failed}, not_instrumented}` | ✅ |
| R3 revise v3 IN PLACE (no consumer existed) + regen drift hash + dated README note | ✅ |
| R4 re-record fixtures (floor visible) + memory-pressure probe | ✅ |
| Unit/BPF/e2e tests | ✅ green (VM, root) |
| Docs (README R2-verbatim + v3-revision note + consumer guidance; KNOWN-LIMITATIONS; CHANGELOG) | ✅ |

- `total` = Σ `by_stage` only (HARD losses). Tolerated is NEVER summed in.
- New BPF counter slot `event_loss_stats[1]` = STAT_PATH_READ_FAILED, incremented
  on the `bpf_probe_read_user_str() <= 0` discard path in `kprobe_openat`. Same
  loss-proof per-CPU mechanism as STAT_RESERVE_FAILED; `STAT_MAX` 1→2.
  `make generate` (clang-18, arm64) regenerated `openat_arm64_bpfel.o` (the .go
  bindings are unchanged — max_entries isn't in them).
- `probe.LossStats()` now returns both BPF stages; `manifest.IsToleratedStage`
  routes them. `cgroupRouter.ReadLoss()` puts path_read_failed in
  `LossReport.Tolerated`; on BPF-read error BOTH BPF stages → not_instrumented.
- `EventLoss.Tolerated` / `LossReport.Tolerated` added; aggregator baseline + delta
  cover tolerated stages (hard+tolerated names are disjoint, one baseline map).
- No-reader (synthetic) case lists hard AND tolerated stages in not_instrumented.

### v3 consumer check (R3)

No consumer of v3 `event_loss` exists. Controller-side ingest of `event_loss` is
unwritten (grep of repo: nothing reads `.event_loss` except the sensor that emits
it, the schema tests, the fixtures, and docs). So v3 was revised in place; drift
hash d02f59…→ d1aa1d0073…. Documented as a one-time, non-precedent exception in
`docs/profile-schema/README.md` and CHANGELOG.

### Fixture results (re-recorded in Lima k8s-dev kind, arm64)

Normal scenarios — `total: 0`, `tolerated.path_read_failed` in the 0–2 idle floor:
static=2, missed-start=2, interp=1, restart=1, restart-3=1, restart-2=0.
Induced-loss (4096-byte ring): `total=1202224` (all bpf_reserve_failed) plus
`tolerated.path_read_failed=10247` from the storm — reserve:read ≈ 117:1, matching
the documented ~100:1.

### Memory-pressure probe (R4)

Method: `hack/mem-pressure-probe.sh` — DEFAULT 256 KB ring buffer (so
bpf_reserve_failed stays ~0 and path_read is isolated), same busybox
`ls -laR /proc /etc /bin /usr /lib` storm, run once at rest and once under a
`stress-ng --vm` neighbour on the VM. Numbers: see "MEM-PRESSURE NUMBERS" below.

**MEM-PRESSURE NUMBERS** (k8s-dev VM, default 256 KB buffer, 60s storm each,
captured-files=23 in BOTH phases → storm genuinely observed, not a false zero):

| Condition | free RAM | path_read_failed | bpf_reserve_failed |
|-----------|----------|------------------|--------------------|
| at rest (baseline) | ~130 MB free / 4.8 G avail | **0** | 0 |
| under `stress-ng --vm 3 --vm-bytes 1700M --vm-keep` | ~80 MB free / 2.8 G avail | **0** | 0 |
| (ref) induced storm, 4096-byte ring | — | 10247 | 1202224 |

**Finding: path_read_failed did NOT scale with memory pressure.** Driving free RAM
to ~80 MB with sustained ~3 G anonymous pressure left the fault at the floor (0).
Reason: the openat filename string is small and hot — just written by the caller
immediately before the syscall — so it is not the kind of page anonymous memory
pressure evicts. The ONLY condition observed to drive the fault large (10247) was
the extreme ring-buffer-starvation storm, i.e. severe CPU/scheduling saturation
(1.2M reserve failures) — and in that regime the HARD gate (`total`) is already
firing, so the tolerated count is moot. So the open question OSS-4b raised
("under memory pressure these faults plausibly scale") is answered **no for
anonymous memory pressure** in this kernel/workload; the fault tracks CPU
saturation / total open volume, not memory footprint.

### Suggested default ceiling (R4 / report item 5)

Recommend a **dual, configurable** gate, defaulting to:
- absolute: `path_read_failed > 16` per container-window (8× the observed 0–2
  idle floor; memory pressure did not move the floor, so a small multiple is safe),
  AND
- fraction: `path_read_failed / Σ files[].count > 0.01` (1% of observed opens),
  which catches the volume-correlated regime where the absolute count rises with
  total open volume rather than with a real quality drop.
Withhold "not observed ⇒ not loaded" only when BOTH (or a configured one) trip.
Always print the count regardless. Rationale: the absolute floor is tiny and
load-independent for memory, but the fault rises with open volume, so an
absolute-only gate would false-fire on high-throughput workloads; the fraction
guard normalises for that.

### Gotchas (in addition to OSS-4's)

- Re-record requires `docker rmi -f tracepod-sensor:fixtures` first (stale-image
  reuse) — same as OSS-4. Did so; image rebuilt fresh.
- stress-ng not preinstalled in k8s-dev VM: `apt-get install -y stress-ng`.

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
