//go:build linux

package probe

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/tracepod/tracepod/manifest"
)

// loadObjsForTest loads the BPF collection into the kernel without attaching the
// kprobes (attachment requires root + a kprobe-capable kernel; loading the maps
// is enough to exercise the event_loss_stats wiring). Skips when the kernel
// rejects the load (no BTF / not privileged / unsupported), matching the
// VM-only nature of the BPF tests.
func loadObjsForTest(t *testing.T) *openatObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock (need privileges): %v", err)
	}
	var objs openatObjects
	if err := loadOpenatObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Skipf("BPF verifier rejected program (kernel/toolchain mismatch): %v", err)
		}
		t.Skipf("cannot load BPF objects (needs privileged BPF-capable kernel): %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// TestEventLossStats_mapPresentAndReadable confirms the schema-v3 event-loss
// wiring end to end on the BPF side: the per-CPU counter map exists in the
// loaded collection, LossStats sums it across CPUs, returns exactly the BPF-side
// stage(s), and reads zero on a freshly loaded program (the true-zero baseline
// the induced-loss e2e scenario then drives nonzero).
func TestEventLossStats_mapPresentAndReadable(t *testing.T) {
	objs := loadObjsForTest(t)

	if objs.EventLossStats == nil {
		t.Fatal("event_loss_stats map missing from loaded collection")
	}

	p := &Probe{objs: *objs}
	stats, err := p.LossStats()
	if err != nil {
		t.Fatalf("LossStats: %v", err)
	}

	// Both BPF-side stages must be present: the hard bpf_reserve_failed and the
	// tolerated path_read_failed (schema v3 + OSS-4b). The caller classifies them.
	want := map[string]bool{
		manifest.LossStageBPFReserveFailed:    true,
		manifest.ToleratedStagePathReadFailed: true,
	}
	for stage := range want {
		if _, ok := stats[stage]; !ok {
			t.Errorf("LossStats missing BPF stage %q", stage)
		}
	}
	for stage, n := range stats {
		if !want[stage] {
			t.Errorf("LossStats returned unexpected stage %q", stage)
		}
		if n != 0 {
			t.Errorf("freshly loaded program: stage %q = %d, want 0 (true zero baseline)", stage, n)
		}
	}
}

// TestEventLossStats_pathReadFailedForced forces a known per-CPU count into the
// tolerated path_read_failed slot (key 1 == STAT_PATH_READ_FAILED) and asserts
// LossStats surfaces it summed across CPUs under the tolerated stage name —
// mirroring the forced-reservation approach for the hard counter (OSS-4b R1 /
// BPF-side test). This proves the new key is wired end to end without needing to
// trigger a real userspace page fault from a test.
func TestEventLossStats_pathReadFailedForced(t *testing.T) {
	objs := loadObjsForTest(t)

	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	vals := make([]uint64, nCPU)
	var want uint64
	for i := range vals {
		vals[i] = uint64(i + 3)
		want += vals[i]
	}
	// Key 1 == STAT_PATH_READ_FAILED.
	if err := objs.EventLossStats.Put(uint32(1), vals); err != nil {
		t.Fatalf("seed per-CPU path_read counter: %v", err)
	}

	p := &Probe{objs: *objs}
	stats, err := p.LossStats()
	if err != nil {
		t.Fatalf("LossStats: %v", err)
	}
	if got := stats[manifest.ToleratedStagePathReadFailed]; got != want {
		t.Errorf("summed path_read_failed: got %d, want %d (sum over %d CPUs)", got, want, nCPU)
	}
	// Forcing the tolerated counter must not bleed into the hard counter.
	if got := stats[manifest.LossStageBPFReserveFailed]; got != 0 {
		t.Errorf("bpf_reserve_failed should remain 0 when only path_read_failed seeded, got %d", got)
	}
}

// TestEventLossStats_perCPUSum forces a known per-CPU count into the map and
// asserts LossStats sums across all CPUs — the property the userspace finaliser
// relies on (a drop is recorded on whichever CPU the kprobe ran).
func TestEventLossStats_perCPUSum(t *testing.T) {
	objs := loadObjsForTest(t)

	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	vals := make([]uint64, nCPU)
	var want uint64
	for i := range vals {
		vals[i] = uint64(i + 1)
		want += vals[i]
	}
	// Key 0 == STAT_RESERVE_FAILED.
	if err := objs.EventLossStats.Put(uint32(0), vals); err != nil {
		t.Fatalf("seed per-CPU counter: %v", err)
	}

	p := &Probe{objs: *objs}
	stats, err := p.LossStats()
	if err != nil {
		t.Fatalf("LossStats: %v", err)
	}
	if got := stats[manifest.LossStageBPFReserveFailed]; got != want {
		t.Errorf("summed bpf_reserve_failed: got %d, want %d (sum over %d CPUs)", got, want, nCPU)
	}
}
