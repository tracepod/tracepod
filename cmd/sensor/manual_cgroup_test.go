//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/internal/ringbuf"
	"github.com/tracepod/tracepod/manifest"
)

// orderingAllower asserts, from inside AllowCgroup, that the router already
// has a live aggregator for the cgroup being allowed — proving
// registerManualCgroup creates the aggregator BEFORE allowlisting the cgroup
// in-kernel (the ordering that mirrors internal/container/nri.go's adopt).
type orderingAllower struct {
	t      *testing.T
	router *cgroupRouter
	called bool
}

func (a *orderingAllower) AllowCgroup(id uint64) error {
	a.called = true
	if a.router.aggFor(id) == nil {
		a.t.Fatalf("AllowCgroup(%d) called before an aggregator was registered for it", id)
	}
	return nil
}

func (a *orderingAllower) DenyCgroup(id uint64) error { return nil }

func TestRegisterManualCgroup_AggregatorBeforeAllow(t *testing.T) {
	r := newRouter(nil, "", "", "", nil, false)
	allower := &orderingAllower{t: t, router: r}

	dir := t.TempDir()
	id, err := registerManualCgroup(r, allower, dir)
	if err != nil {
		t.Fatalf("registerManualCgroup: %v", err)
	}
	if !allower.called {
		t.Fatal("AllowCgroup was never called")
	}
	if r.aggFor(id) == nil {
		t.Fatalf("no aggregator registered for cgroup %d after registerManualCgroup", id)
	}
}

// recordingManualAllower is a no-op CgroupAllower used by tests that only
// care about the aggregator/event-recording behaviour, not ordering.
type recordingManualAllower struct {
	allowed []uint64
}

func (a *recordingManualAllower) AllowCgroup(id uint64) error {
	a.allowed = append(a.allowed, id)
	return nil
}

func (a *recordingManualAllower) DenyCgroup(id uint64) error { return nil }

// newOpenatEvent builds a synthetic openat ringbuf.Event the way the BPF
// program would encode one, for feeding directly into r.handle in tests.
func newOpenatEvent(cgroupID uint64, pid uint32, path string) ringbuf.Event {
	var e ringbuf.Event
	e.Type = ringbuf.EventTypeOpenat
	e.Pid = pid
	e.CgroupID = cgroupID
	copy(e.Filename[:], path)
	return e
}

func TestRegisterManualCgroup_EventsAreRecorded(t *testing.T) {
	r := newRouter(nil, "", "", "", nil, false)
	allower := &recordingManualAllower{}

	dir := t.TempDir()
	id, err := registerManualCgroup(r, allower, dir)
	if err != nil {
		t.Fatalf("registerManualCgroup: %v", err)
	}

	// Feed a synthetic file-open event for the manually-registered cgroup
	// directly into the router's dispatch path, exactly as the ring buffer
	// consumer would.
	r.handle(newOpenatEvent(id, 4242, "/etc/hosts"))

	agg := r.aggFor(id)
	if agg == nil {
		t.Fatalf("aggregator for cgroup %d disappeared", id)
	}
	snap := agg.Snapshot()
	if _, found := snap.Files["/etc/hosts"]; !found {
		t.Errorf("aggregator did not record /etc/hosts; files=%+v", snap.Files)
	}

	if got := r.untrackedCgroup.Load(); got != 0 {
		t.Errorf("untrackedCgroup = %d, want 0 — the manual cgroup's own event must not be counted as loss", got)
	}
}

func TestRegisterManualCgroup_UntrustedProvenance(t *testing.T) {
	r := newRouter(nil, "", "", "", nil, false)
	allower := &recordingManualAllower{}

	dir := t.TempDir()
	id, err := registerManualCgroup(r, allower, dir)
	if err != nil {
		t.Fatalf("registerManualCgroup: %v", err)
	}

	snap := r.aggFor(id).Snapshot()
	if snap.Coverage.AdoptionMode != manifest.AdoptionUnknown {
		t.Errorf("AdoptionMode = %q, want empty/unknown — a manual cgroup gives no start-anchoring guarantee", snap.Coverage.AdoptionMode)
	}
	if snap.Coverage.ProcessStartObserved {
		t.Error("ProcessStartObserved = true, want false — we cannot prove the cgroup was empty at attach")
	}
}

// TestManualContainerID_SafeForOnContainerStartSlice is a regression test for
// a panic found during AL2023 end-to-end testing: onContainerStart's tracking
// log line does info.ContainerID[:12], which panics
// ("slice bounds out of range [:12] with length 11") for a small cgroup ID
// (observed: inode 5053 -> "manual-5053", 11 bytes) once the naive
// "manual-"+strconv.FormatUint(id, 10) form was used. This test exercises
// onContainerStart directly with a deliberately small cgroup ID so it fails
// (by panicking) if manualContainerID's zero-padding is ever removed or
// weakened, independent of whatever inode t.TempDir() happens to allocate on
// the machine running the test.
func TestManualContainerID_SafeForOnContainerStartSlice(t *testing.T) {
	r := newRouter(nil, "", "", "", nil, false)

	const smallCgroupID = uint64(1) // worst case: single-digit inode

	id := manualContainerID(smallCgroupID)
	if strings.Contains(id, "/") {
		t.Errorf("manualContainerID(%d) = %q contains '/', unsafe as a profile directory name", smallCgroupID, id)
	}

	// This must not panic: onContainerStart's log line slices ContainerID[:12].
	r.onContainerStart(container.StartInfo{
		ContainerID:           id,
		CgroupID:              smallCgroupID,
		AttachTime:            time.Now().UTC(),
		ProcessAlreadyRunning: true,
	})

	if r.aggFor(smallCgroupID) == nil {
		t.Fatalf("no aggregator registered for cgroup %d after onContainerStart", smallCgroupID)
	}
}

func TestRegisterManualCgroup_ResolveErrorDoesNotAllow(t *testing.T) {
	r := newRouter(nil, "", "", "", nil, false)
	allower := &recordingManualAllower{}

	nonexistent := t.TempDir() + "/does-not-exist"
	if _, err := os.Stat(nonexistent); err == nil {
		t.Fatalf("test setup: %s unexpectedly exists", nonexistent)
	}

	_, err := registerManualCgroup(r, allower, nonexistent)
	if err == nil {
		t.Fatal("expected an error resolving a nonexistent cgroup path, got nil")
	}
	if len(allower.allowed) != 0 {
		t.Errorf("AllowCgroup was called %d times despite a resolve error", len(allower.allowed))
	}
}
