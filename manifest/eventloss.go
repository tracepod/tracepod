package manifest

// Event-loss instrumentation (schema v3).
//
// The sensor can drop events at several points along the path from the BPF
// programs to the assembled profile. A downstream consumer that wants to make a
// "not observed ⇒ not loaded" claim must know whether the observation window was
// lossy: dropped events make a busy window look quiet, so silence is only
// meaningful when nothing was dropped. These counters make loss machine-visible.
//
// Loss-point audit (every point on the event path; see
// docs/profile-schema/README.md and docs/KNOWN-LIMITATIONS.md). Two loss classes:
//
// HARD losses — counted toward EventLoss.Total; the strict-zero gate. A clean
// window reports total 0 and a consumer may then read "not observed ⇒ not loaded":
//
//	BPF program  ── bpf_ringbuf_reserve() returns NULL when the ring is full
//	                (userspace not draining fast enough)         → bpf_reserve_failed
//	ringbuf map  ── (no separate loss point: a full ring surfaces in the kernel
//	                as a reserve failure, counted above; the cilium/ebpf RINGBUF
//	                reader has no lost-sample concept — unlike a PERF buffer it
//	                reads every committed record, so there is nothing to count
//	                here. See the README "reader" note.)
//	consumer     ── a committed record too short to decode is skipped → decode_failed
//	router       ── an event for a cgroup with no live aggregator (the brief race
//	                between the BPF allowlist and the userspace aggregator map at
//	                container start/stop) is dropped            → untracked_cgroup
//
// TOLERATED losses — counted and reported in EventLoss.Tolerated, but NEVER folded
// into Total; the consumer gates them with its own conservative, configurable
// ceiling and must surface the counts in any evidence it emits:
//
//	BPF program  ── bpf_probe_read_user_str() faults on the openat filename
//	                pointer (e.g. the user page is not yet present): the
//	                reservation succeeds but the event is discarded because the
//	                path could not be read — a lost observation, the file open
//	                went unidentified.                          → path_read_failed
//
// path_read_failed is a real lost observation, so it is counted (a consumer that
// saw total 0 with no visibility of these faults would wrongly conclude "nothing
// lost" while file opens went unidentified). It is a TOLERATED category, separate
// from Total, because it has a known load-independent idle floor (0–2 per
// container even at idle): folding it into Total would put a permanent floor under
// the strict-zero gate on hard losses and defeat it (every window would look
// lossy). Whether it stays bounded under memory pressure is the open question the
// consumer's ceiling must be configured for (see docs/profile-schema/README.md);
// the dominant, load-correlated loss — bpf_reserve_failed — outnumbers read
// faults by ~100:1 under the induced-loss storm. It is NOT placed in
// not_instrumented, which is reserved for in-scope points that could not be
// counted: as of schema v3 it IS counted.
//
// Counts are PROCESS-WIDE and per profiling WINDOW, never per container: a
// buffer-level drop cannot be attributed to one container, so any loss during a
// container's window taints every container observed in that window (the
// conservative direction). See EventLoss.
const (
	// LossStageBPFReserveFailed counts bpf_ringbuf_reserve() failures across all
	// three kprobes — the primary buffer-pressure loss point. Counted in-kernel
	// (a per-CPU map) because userspace never sees a reservation that never
	// happened.
	LossStageBPFReserveFailed = "bpf_reserve_failed"

	// LossStageDecodeFailed counts committed ring-buffer records too short to
	// decode into an Event (the consumer skips them). Counted in userspace.
	LossStageDecodeFailed = "decode_failed"

	// LossStageUntrackedCgroup counts events the kernel emitted for an allowed
	// cgroup that arrived while the router had no live aggregator for it — the
	// brief window between the BPF allowlist and the userspace aggregator map at
	// container start, or in-flight events after stop. Counted in userspace.
	LossStageUntrackedCgroup = "untracked_cgroup"

	// ToleratedStagePathReadFailed counts openat events discarded because
	// bpf_probe_read_user_str() faulted on the userspace filename pointer (the
	// reservation succeeded but the path was unreadable, so the file open went
	// unidentified). Counted in-kernel (a per-CPU map). It is a TOLERATED loss: a
	// counted observation lost for a reason with a known intrinsic floor, reported
	// in event_loss.tolerated and gated by the consumer's own ceiling — never
	// folded into event_loss.total. See the package audit above.
	ToleratedStagePathReadFailed = "path_read_failed"
)

// LossStages is the canonical, ordered set of HARD audited loss points — the ones
// summed into event_loss.total (the strict-zero gate). Every emitted profile's
// event_loss.by_stage carries exactly these keys (minus any a reader reports as
// not-instrumented at read time — those move to not_instrumented so a stage never
// reads a false zero). Keep in audit order.
var LossStages = []string{
	LossStageBPFReserveFailed,
	LossStageDecodeFailed,
	LossStageUntrackedCgroup,
}

// ToleratedStages is the canonical, ordered set of TOLERATED audited loss points.
// They are counted and reported in event_loss.tolerated but excluded from
// event_loss.total: each has a known intrinsic floor, so a consumer gates them
// with its own conservative, configurable ceiling rather than the strict-zero
// gate applied to LossStages. Every emitted profile's event_loss.tolerated
// carries exactly these keys (minus any a reader reports as not-instrumented).
var ToleratedStages = []string{
	ToleratedStagePathReadFailed,
}

// IsToleratedStage reports whether a loss-stage name belongs to the tolerated
// category (event_loss.tolerated) rather than the hard category (event_loss.total
// via by_stage). The sensor's loss reader uses it to route BPF-side counters,
// which span both classes, into the correct bucket.
func IsToleratedStage(stage string) bool {
	for _, s := range ToleratedStages {
		if s == stage {
			return true
		}
	}
	return false
}

// EventLoss is the per-window event-loss report carried by every schema-v3
// profile (top-level event_loss).
//
// Semantics a consumer must honour:
//
//   - Window-level, not per-container. The counts cover the container's
//     profiling window; buffer drops are not attributable to one container, so
//     any nonzero total taints the "not observed ⇒ not loaded" conclusion for
//     EVERY container observed in that window.
//   - Total is the gate, and counts HARD losses only. Treat any nonzero Total as
//     grounds to withhold a "never loaded" claim for the whole window; ByStage is
//     for diagnosis only.
//   - Tolerated losses are counted observations lost for reasons with a known
//     intrinsic floor. A consumer MUST gate them with its own (conservative,
//     configurable) ceiling and MUST surface the counts in any evidence it emits
//     — it must never fold them into Total, and never ignore them.
//   - Zero is a claim. Total == 0 means "instrumented at every audited HARD loss
//     point and nothing was lost there" — never "we did not count." A loss point
//     that could not be instrumented is named in NotInstrumented and omitted from
//     ByStage/Tolerated, so it never masquerades as a zero.
//
// Invariant: Total == Σ ByStage. Tolerated is excluded from Total by construction.
type EventLoss struct {
	Total uint64 `json:"total"`

	// ByStage maps each instrumented HARD loss stage to its count for the window.
	// Always non-nil. Contains every LossStages entry that was instrumented for
	// this window (its count may be 0 — an explicit "counted, lost nothing"). Its
	// values sum to Total.
	ByStage map[string]uint64 `json:"by_stage"`

	// Tolerated maps each instrumented TOLERATED loss stage to its count for the
	// window (every ToleratedStages entry that was instrumented; a 0 is an
	// explicit "counted, lost nothing"). Always non-nil. These counts are
	// deliberately EXCLUDED from Total: the consumer gates them against its own
	// configurable ceiling and surfaces them separately. They must never be folded
	// into Total nor silently dropped.
	Tolerated map[string]uint64 `json:"tolerated"`

	// NotInstrumented lists audited loss points (hard or tolerated) that were NOT
	// counted for this window (e.g. a runtime failure reading the in-kernel
	// counter). Stages here are absent from ByStage and Tolerated so they never
	// read as a false zero. Always non-nil; empty in the normal fully-instrumented
	// case (this sensor instruments every audited point as of schema v3).
	NotInstrumented []string `json:"not_instrumented"`
}

// LossReport is a single cumulative, process-wide read of the sensor's loss
// counters. The aggregator captures one at window start (baseline) and one at
// snapshot, emitting the per-window delta as EventLoss. Implemented by the
// sensor, which sums the in-kernel per-CPU map and the userspace atomics.
type LossReport struct {
	// ByStage holds the cumulative count for each instrumented HARD stage since
	// sensor start. Monotonic non-decreasing.
	ByStage map[string]uint64

	// Tolerated holds the cumulative count for each instrumented TOLERATED stage
	// since sensor start. Monotonic non-decreasing. Kept separate from ByStage so
	// the aggregator never sums it into Total.
	Tolerated map[string]uint64

	// NotInstrumented lists stages (hard or tolerated) that could not be read at
	// this instant. Such stages must NOT appear in ByStage or Tolerated (a missing
	// read is not a zero).
	NotInstrumented []string
}

// LossReader yields the sensor's current cumulative loss counters. A nil reader
// on an aggregator means the window was not instrumented at all: its EventLoss
// reports every stage as not_instrumented rather than a false zero.
type LossReader interface {
	ReadLoss() LossReport
}
