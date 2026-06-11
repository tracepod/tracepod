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
// docs/profile-schema/README.md and docs/KNOWN-LIMITATIONS.md):
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
// CONSIDERED BUT NOT COUNTED — bpf_probe_read_user_str() faulting on the openat
// filename pointer. The reservation succeeds but the event is discarded because
// the path could not be read (e.g. the user page is not yet present). This is a
// path-read fault, a different class from the capacity/transport drops above: it
// has a load-independent nonzero floor (0–2 per container even at idle), so
// folding it into total would put a permanent floor under the consumer's
// lossy-window gate and defeat it (every window would look lossy). The dominant,
// load-correlated loss — bpf_reserve_failed — is fully counted (under the
// induced-loss storm it outnumbers read faults by ~100:1). It is therefore
// documented here and out of scope for event_loss; it is NOT placed in
// not_instrumented, which is reserved for in-scope points that could not be
// counted, not for points deliberately scoped out.
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
)

// LossStages is the canonical, ordered set of audited loss points. Every emitted
// profile's event_loss.by_stage carries exactly these keys (minus any a reader
// reports as not-instrumented at read time — those move to not_instrumented so a
// stage never reads a false zero). Keep in audit order.
var LossStages = []string{
	LossStageBPFReserveFailed,
	LossStageDecodeFailed,
	LossStageUntrackedCgroup,
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
//   - Total is the gate. Treat any nonzero Total as grounds to withhold a
//     "never loaded" claim for the whole window; ByStage is for diagnosis only.
//   - Zero is a claim. Total == 0 means "instrumented at every audited loss
//     point and nothing was lost" — never "we did not count." A loss point that
//     could not be instrumented is named in NotInstrumented and omitted from
//     ByStage, so it never masquerades as a zero.
//
// Invariant: Total == Σ ByStage.
type EventLoss struct {
	Total uint64 `json:"total"`

	// ByStage maps each instrumented loss stage to its count for the window.
	// Always non-nil. Contains every LossStages entry that was instrumented for
	// this window (its count may be 0 — an explicit "counted, lost nothing").
	ByStage map[string]uint64 `json:"by_stage"`

	// NotInstrumented lists audited loss points that were NOT counted for this
	// window (e.g. a runtime failure reading the in-kernel counter). Stages here
	// are absent from ByStage so they never read as a false zero. Always
	// non-nil; empty in the normal fully-instrumented case.
	NotInstrumented []string `json:"not_instrumented"`
}

// LossReport is a single cumulative, process-wide read of the sensor's loss
// counters. The aggregator captures one at window start (baseline) and one at
// snapshot, emitting the per-window delta as EventLoss. Implemented by the
// sensor, which sums the in-kernel per-CPU map and the userspace atomics.
type LossReport struct {
	// ByStage holds the cumulative count for each instrumented stage since
	// sensor start. Monotonic non-decreasing.
	ByStage map[string]uint64

	// NotInstrumented lists stages that could not be read at this instant. Such
	// stages must NOT appear in ByStage (a missing read is not a zero).
	NotInstrumented []string
}

// LossReader yields the sensor's current cumulative loss counters. A nil reader
// on an aggregator means the window was not instrumented at all: its EventLoss
// reports every stage as not_instrumented rather than a false zero.
type LossReader interface {
	ReadLoss() LossReport
}
