package manifest_test

import (
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// fakeLossReader is a programmable manifest.LossReader. Tests mutate byStage /
// tolerated between the baseline read (SetLossReader) and the snapshot read to
// inject loss.
type fakeLossReader struct {
	byStage         map[string]uint64
	tolerated       map[string]uint64
	notInstrumented []string
}

func (f *fakeLossReader) ReadLoss() manifest.LossReport {
	cp := make(map[string]uint64, len(f.byStage))
	for k, v := range f.byStage {
		cp[k] = v
	}
	var tol map[string]uint64
	if f.tolerated != nil {
		tol = make(map[string]uint64, len(f.tolerated))
		for k, v := range f.tolerated {
			tol[k] = v
		}
	}
	return manifest.LossReport{ByStage: cp, Tolerated: tol, NotInstrumented: append([]string(nil), f.notInstrumented...)}
}

func sumByStage(by map[string]uint64) uint64 {
	var t uint64
	for _, v := range by {
		t += v
	}
	return t
}

// TestEventLoss_perWindowDelta verifies per-stage accumulation: only loss that
// happens after the baseline is captured (the window) is reported, and the sum
// invariant holds.
func TestEventLoss_perWindowDelta(t *testing.T) {
	r := &fakeLossReader{byStage: map[string]uint64{
		// Pre-existing cumulative loss from before this window — must NOT count.
		manifest.LossStageBPFReserveFailed: 100,
		manifest.LossStageDecodeFailed:     0,
		manifest.LossStageUntrackedCgroup:  2,
	}}

	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r) // baseline captured here

	// Loss accrues during the window.
	r.byStage[manifest.LossStageBPFReserveFailed] = 142 // +42
	r.byStage[manifest.LossStageDecodeFailed] = 3       // +3
	r.byStage[manifest.LossStageUntrackedCgroup] = 2    // +0

	el := a.Snapshot().EventLoss

	if got := el.ByStage[manifest.LossStageBPFReserveFailed]; got != 42 {
		t.Errorf("bpf_reserve_failed: got %d, want 42", got)
	}
	if got := el.ByStage[manifest.LossStageDecodeFailed]; got != 3 {
		t.Errorf("decode_failed: got %d, want 3", got)
	}
	if got := el.ByStage[manifest.LossStageUntrackedCgroup]; got != 0 {
		t.Errorf("untracked_cgroup: got %d, want 0", got)
	}
	if el.Total != 45 {
		t.Errorf("total: got %d, want 45", el.Total)
	}
	if el.Total != sumByStage(el.ByStage) {
		t.Errorf("sum invariant violated: total=%d sum(by_stage)=%d", el.Total, sumByStage(el.ByStage))
	}
	if len(el.NotInstrumented) != 0 {
		t.Errorf("not_instrumented should be empty when fully instrumented, got %v", el.NotInstrumented)
	}
	// Every instrumented stage must be explicitly present (a 0 is a claim).
	for _, st := range manifest.LossStages {
		if _, ok := el.ByStage[st]; !ok {
			t.Errorf("stage %q missing from by_stage — an instrumented stage must report its (possibly zero) count", st)
		}
	}
}

// TestEventLoss_zeroIsAClaim_fullyInstrumented: when a reader is attached and
// nothing is lost, total is 0, every stage is present at 0, and nothing is
// listed not_instrumented. Zero here means "counted, lost nothing".
func TestEventLoss_zeroIsAClaim_fullyInstrumented(t *testing.T) {
	r := &fakeLossReader{byStage: map[string]uint64{
		manifest.LossStageBPFReserveFailed: 7,
		manifest.LossStageDecodeFailed:     7,
		manifest.LossStageUntrackedCgroup:  7,
	}}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r) // baseline == current → all deltas 0

	el := a.Snapshot().EventLoss
	if el.Total != 0 {
		t.Fatalf("total: got %d, want 0", el.Total)
	}
	if len(el.ByStage) != len(manifest.LossStages) {
		t.Fatalf("by_stage must list all %d stages, got %d: %v", len(manifest.LossStages), len(el.ByStage), el.ByStage)
	}
	if len(el.NotInstrumented) != 0 {
		t.Errorf("not_instrumented should be empty, got %v", el.NotInstrumented)
	}
}

// TestEventLoss_noReaderIsNotInstrumented: an aggregator with no reader did not
// count — it must report every stage (hard AND tolerated) as not_instrumented,
// never a false zero.
func TestEventLoss_noReaderIsNotInstrumented(t *testing.T) {
	a := manifest.NewAggregator("c", "")
	el := a.Snapshot().EventLoss

	if el.Total != 0 {
		t.Errorf("total: got %d, want 0", el.Total)
	}
	if len(el.ByStage) != 0 {
		t.Errorf("by_stage must be empty when uninstrumented (no false zeros), got %v", el.ByStage)
	}
	if len(el.Tolerated) != 0 {
		t.Errorf("tolerated must be empty when uninstrumented (no false zeros), got %v", el.Tolerated)
	}
	wantN := len(manifest.LossStages) + len(manifest.ToleratedStages)
	if len(el.NotInstrumented) != wantN {
		t.Fatalf("not_instrumented must list all %d stages (hard+tolerated), got %v", wantN, el.NotInstrumented)
	}
	for _, st := range append(append([]string{}, manifest.LossStages...), manifest.ToleratedStages...) {
		found := false
		for _, n := range el.NotInstrumented {
			if n == st {
				found = true
			}
		}
		if !found {
			t.Errorf("stage %q missing from not_instrumented", st)
		}
	}
}

// TestEventLoss_toleratedAccumulatesAndExcludedFromTotal: a tolerated stage is
// counted as a per-window delta in tolerated, present even at zero, and NEVER
// folded into total — the strict-zero gate on hard losses keeps passing while
// path_read_failed is nonzero. (R1/R2: the core invariant of this amendment.)
func TestEventLoss_toleratedAccumulatesAndExcludedFromTotal(t *testing.T) {
	r := &fakeLossReader{
		byStage: map[string]uint64{
			manifest.LossStageBPFReserveFailed: 5,
			manifest.LossStageDecodeFailed:     0,
			manifest.LossStageUntrackedCgroup:  0,
		},
		tolerated: map[string]uint64{
			manifest.ToleratedStagePathReadFailed: 10, // pre-window floor — must NOT count
		},
	}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r) // baseline captured here

	// Only tolerated loss accrues during the window; no hard loss.
	r.tolerated[manifest.ToleratedStagePathReadFailed] = 12 // +2 (the idle floor)

	el := a.Snapshot().EventLoss

	if got := el.Tolerated[manifest.ToleratedStagePathReadFailed]; got != 2 {
		t.Errorf("tolerated.path_read_failed: got %d, want 2 (per-window delta)", got)
	}
	// The strict-zero gate on hard losses must still read zero.
	if el.Total != 0 {
		t.Errorf("total must exclude tolerated losses: got %d, want 0", el.Total)
	}
	if el.Total != sumByStage(el.ByStage) {
		t.Errorf("sum invariant: total=%d != sum(by_stage)=%d", el.Total, sumByStage(el.ByStage))
	}
	if len(el.NotInstrumented) != 0 {
		t.Errorf("not_instrumented should be empty when fully instrumented, got %v", el.NotInstrumented)
	}
	// Every tolerated stage must be explicitly present (a 0 is a claim).
	for _, st := range manifest.ToleratedStages {
		if _, ok := el.Tolerated[st]; !ok {
			t.Errorf("tolerated stage %q missing — an instrumented stage must report its (possibly zero) count", st)
		}
	}
}

// TestEventLoss_pathReadFailedOnlyInTolerated is the regression guard for OSS-4b:
// path_read_failed must appear in tolerated and in NO other bucket (not by_stage,
// not not_instrumented) when fully instrumented, and must never move total.
func TestEventLoss_pathReadFailedOnlyInTolerated(t *testing.T) {
	r := &fakeLossReader{
		byStage: map[string]uint64{
			manifest.LossStageBPFReserveFailed: 0,
			manifest.LossStageDecodeFailed:     0,
			manifest.LossStageUntrackedCgroup:  0,
		},
		tolerated: map[string]uint64{manifest.ToleratedStagePathReadFailed: 0},
	}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r)
	r.tolerated[manifest.ToleratedStagePathReadFailed] = 999

	el := a.Snapshot().EventLoss

	if _, ok := el.Tolerated[manifest.ToleratedStagePathReadFailed]; !ok {
		t.Error("path_read_failed must appear in tolerated")
	}
	if el.Tolerated[manifest.ToleratedStagePathReadFailed] != 999 {
		t.Errorf("tolerated.path_read_failed: got %d, want 999", el.Tolerated[manifest.ToleratedStagePathReadFailed])
	}
	if _, ok := el.ByStage[manifest.ToleratedStagePathReadFailed]; ok {
		t.Error("path_read_failed must NOT appear in by_stage")
	}
	for _, n := range el.NotInstrumented {
		if n == manifest.ToleratedStagePathReadFailed {
			t.Error("path_read_failed must NOT appear in not_instrumented when instrumented")
		}
	}
	if el.Total != 0 {
		t.Errorf("total must be 0 (path_read_failed excluded), got %d", el.Total)
	}
}

// TestEventLoss_toleratedNotInstrumented: when the reader cannot read the
// tolerated counter, it is listed in not_instrumented and absent from tolerated —
// never a false zero (the zero-is-a-claim rule applies to tolerated stages too).
func TestEventLoss_toleratedNotInstrumented(t *testing.T) {
	r := &fakeLossReader{
		byStage: map[string]uint64{
			manifest.LossStageBPFReserveFailed: 0,
			manifest.LossStageDecodeFailed:     0,
			manifest.LossStageUntrackedCgroup:  0,
		},
		notInstrumented: []string{manifest.ToleratedStagePathReadFailed},
	}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r)

	el := a.Snapshot().EventLoss

	if _, ok := el.Tolerated[manifest.ToleratedStagePathReadFailed]; ok {
		t.Error("uninstrumented path_read_failed must not appear in tolerated as a false zero")
	}
	found := false
	for _, n := range el.NotInstrumented {
		if n == manifest.ToleratedStagePathReadFailed {
			found = true
		}
	}
	if !found {
		t.Errorf("path_read_failed must be listed in not_instrumented, got %v", el.NotInstrumented)
	}
	if el.Total != 0 {
		t.Errorf("total: got %d, want 0", el.Total)
	}
}

// TestEventLoss_partialInstrumentation: a stage the reader reports as
// not-instrumented at read time is excluded from by_stage (no false zero) and
// listed in not_instrumented; the others still report their deltas and the sum
// invariant holds over the instrumented stages only.
func TestEventLoss_partialInstrumentation(t *testing.T) {
	r := &fakeLossReader{
		byStage: map[string]uint64{
			manifest.LossStageDecodeFailed:    0,
			manifest.LossStageUntrackedCgroup: 0,
		},
		// The in-kernel counter could not be read — honestly uninstrumented.
		notInstrumented: []string{
			manifest.LossStageBPFReserveFailed,
		},
	}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r)

	r.byStage[manifest.LossStageDecodeFailed] = 4 // +4

	el := a.Snapshot().EventLoss

	if _, ok := el.ByStage[manifest.LossStageBPFReserveFailed]; ok {
		t.Error("uninstrumented bpf_reserve_failed must not appear in by_stage as a false zero")
	}
	if got := el.ByStage[manifest.LossStageDecodeFailed]; got != 4 {
		t.Errorf("decode_failed: got %d, want 4", got)
	}
	if el.Total != 4 || el.Total != sumByStage(el.ByStage) {
		t.Errorf("sum invariant: total=%d sum=%d, want 4", el.Total, sumByStage(el.ByStage))
	}
	if len(el.NotInstrumented) != 1 || el.NotInstrumented[0] != manifest.LossStageBPFReserveFailed {
		t.Errorf("not_instrumented: got %v, want [%s]", el.NotInstrumented, manifest.LossStageBPFReserveFailed)
	}
}

// TestEventLoss_nonzeroReachable proves a nonzero total is representable end to
// end (the consumer's gate must be able to fire).
func TestEventLoss_nonzeroReachable(t *testing.T) {
	r := &fakeLossReader{byStage: map[string]uint64{manifest.LossStageBPFReserveFailed: 0}}
	a := manifest.NewAggregator("c", "")
	a.SetLossReader(r)
	r.byStage[manifest.LossStageBPFReserveFailed] = 999

	el := a.Snapshot().EventLoss
	if el.Total == 0 {
		t.Fatal("expected nonzero total to be reachable")
	}
	if el.ByStage[manifest.LossStageBPFReserveFailed] != 999 {
		t.Errorf("bpf_reserve_failed: got %d, want 999", el.ByStage[manifest.LossStageBPFReserveFailed])
	}
}
