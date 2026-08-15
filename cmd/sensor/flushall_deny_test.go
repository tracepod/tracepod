//go:build linux

package main

import (
	"sync"
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// recordingAllower captures the order of allowlist mutations so a test can
// assert that a cgroup is denied before its aggregator is dropped.
type recordingAllower struct {
	mu     sync.Mutex
	denied []uint64
	err    error
}

func (r *recordingAllower) AllowCgroup(id uint64) error { return nil }

func (r *recordingAllower) DenyCgroup(id uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denied = append(r.denied, id)
	return r.err
}

func (r *recordingAllower) denyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.denied)
}

// TestFlushAll_DeniesEveryCgroup pins the invariant that no cgroup may remain
// allowlisted without a live aggregator.
//
// flushAll drops every aggregator under the lock and then POSTs each profile
// serially, with a multi-second timeout per POST. Without the deny, every
// cgroup on the node stays allowlisted for that whole window, so `handle`
// counts its events as untracked_cgroup hard loss — and ReadLoss reports that
// counter PROCESS-WIDE. The result was fabricated hard loss attributed to
// every profile flushed after the first, on every ordinary shutdown.
func TestFlushAll_DeniesEveryCgroup(t *testing.T) {
	allower := &recordingAllower{}
	r := &cgroupRouter{
		aggs:         make(map[uint64]*manifest.Aggregator),
		ctrToCgroup:  make(map[string]uint64),
		cgroupFSPath: make(map[uint64]string),
		targets:      make(map[uint64]*postTarget),
		denyList:     manifest.DefaultDenyList(),
		allower:      allower,
		// profileDir and controllerURL both empty: flush is a no-op sink, so
		// the test exercises the claim/deny bookkeeping in isolation.
	}

	cgroups := []uint64{101, 202, 303}
	for _, cg := range cgroups {
		agg := manifest.NewAggregator("ctr-"+string(rune('a'+cg%26)), "")
		r.aggs[cg] = agg
		r.targets[cg] = &postTarget{containerID: "ctr"}
	}

	r.flushAll()

	if got := allower.denyCount(); got != len(cgroups) {
		t.Fatalf("DenyCgroup called %d times, want %d — cgroups left allowlisted "+
			"with no aggregator produce fabricated untracked_cgroup loss", got, len(cgroups))
	}

	denied := map[uint64]bool{}
	for _, id := range allower.denied {
		denied[id] = true
	}
	for _, cg := range cgroups {
		if !denied[cg] {
			t.Errorf("cgroup %d was never denied", cg)
		}
	}

	// The maps must also be cleared, so a later onContainerStop cannot double-flush.
	if len(r.aggs) != 0 || len(r.targets) != 0 || len(r.cgroupFSPath) != 0 {
		t.Errorf("flushAll left state behind: aggs=%d targets=%d paths=%d",
			len(r.aggs), len(r.targets), len(r.cgroupFSPath))
	}
}

// TestFlushAll_NilAllowerIsSafe covers the standalone/bare-metal path and the
// existing tests, which construct a router with no probe attached.
func TestFlushAll_NilAllowerIsSafe(t *testing.T) {
	r := &cgroupRouter{
		aggs:         make(map[uint64]*manifest.Aggregator),
		ctrToCgroup:  make(map[string]uint64),
		cgroupFSPath: make(map[uint64]string),
		targets:      make(map[uint64]*postTarget),
		denyList:     manifest.DefaultDenyList(),
		allower:      nil,
	}
	r.aggs[7] = manifest.NewAggregator("ctr-nil", "")
	r.targets[7] = &postTarget{containerID: "ctr-nil"}

	r.flushAll() // must not panic

	if len(r.aggs) != 0 {
		t.Errorf("flushAll did not clear aggs with a nil allower")
	}
}
