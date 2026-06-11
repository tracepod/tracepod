package manifest_test

import (
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// fakeLossReader is a programmable manifest.LossReader. Tests mutate byStage
// between the baseline read (SetLossReader) and the snapshot read to inject loss.
type fakeLossReader struct {
	byStage         map[string]uint64
	notInstrumented []string
}

func (f *fakeLossReader) ReadLoss() manifest.LossReport {
	cp := make(map[string]uint64, len(f.byStage))
	for k, v := range f.byStage {
		cp[k] = v
	}
	return manifest.LossReport{ByStage: cp, NotInstrumented: append([]string(nil), f.notInstrumented...)}
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
// count — it must report every stage as not_instrumented, never a false zero.
func TestEventLoss_noReaderIsNotInstrumented(t *testing.T) {
	a := manifest.NewAggregator("c", "")
	el := a.Snapshot().EventLoss

	if el.Total != 0 {
		t.Errorf("total: got %d, want 0", el.Total)
	}
	if len(el.ByStage) != 0 {
		t.Errorf("by_stage must be empty when uninstrumented (no false zeros), got %v", el.ByStage)
	}
	if len(el.NotInstrumented) != len(manifest.LossStages) {
		t.Fatalf("not_instrumented must list all %d stages, got %v", len(manifest.LossStages), el.NotInstrumented)
	}
	for _, st := range manifest.LossStages {
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
