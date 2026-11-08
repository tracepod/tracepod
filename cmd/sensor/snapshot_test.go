//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/manifest"
)

const snapCtr = "ctr-s00000000000000000000000000000000000000000000000000000000000"

// fakeClock is a manually advanced clock for snapshot scheduling.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// snapReceiver records decoded manifests POSTed to the ingest endpoint.
type snapReceiver struct {
	mu     sync.Mutex
	bodies []manifest.Manifest
	status int
	gate   chan struct{} // when non-nil, each POST blocks until it yields/closes
	hit    chan struct{} // signalled on arrival of each POST (buffered)
}

func newSnapReceiver(t *testing.T) (*snapReceiver, *httptest.Server) {
	t.Helper()
	rc := &snapReceiver{status: http.StatusCreated, hit: make(chan struct{}, 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var m manifest.Manifest
		_ = json.Unmarshal(b, &m)
		rc.mu.Lock()
		gate, status := rc.gate, rc.status
		rc.mu.Unlock()
		select {
		case rc.hit <- struct{}{}:
		default:
		}
		if gate != nil {
			<-gate
		}
		rc.mu.Lock()
		rc.bodies = append(rc.bodies, m)
		rc.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return rc, srv
}

func (rc *snapReceiver) got() []manifest.Manifest {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]manifest.Manifest(nil), rc.bodies...)
}

func (rc *snapReceiver) setStatus(s int) {
	rc.mu.Lock()
	rc.status = s
	rc.mu.Unlock()
}

// snapRouter builds a router with interim snapshots enabled and a fake clock,
// starts one resolved container (cgroup 1) and returns them.
func snapRouter(t *testing.T, url string, interval time.Duration, dep string) (*cgroupRouter, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newRouter(nil, "", url, "node-1", &fakeResolver{dep: dep, image: "nginx:1"}, false)
	r.snapshotInterval = interval
	r.now = clk.Now
	r.onContainerStart(container.StartInfo{
		ContainerID: snapCtr, CgroupID: 1,
		Pod: container.PodMeta{Namespace: "ns", Name: "web-1"},
	})
	waitStartResolve(t, r, 1)
	return r, clk
}

func stopSnapCtr(r *cgroupRouter) {
	r.onContainerStop(snapCtr, 1, container.PodMeta{Namespace: "ns", Name: "web-1"})
}

func TestSnapshotInterval_RejectsBelowMinimum(t *testing.T) {
	for _, d := range []time.Duration{time.Nanosecond, time.Second, 9999 * time.Millisecond, -time.Second} {
		if err := validateSnapshotInterval(d); err == nil {
			t.Errorf("interval %s accepted, want error", d)
		}
	}
	for _, d := range []time.Duration{0, 10 * time.Second, 20 * time.Second, 5 * time.Minute} {
		if err := validateSnapshotInterval(d); err != nil {
			t.Errorf("interval %s rejected: %v", d, err)
		}
	}
	if err := validateSnapshotInterval(time.Second); err == nil || !strings.Contains(err.Error(), "0 or >= 10s") {
		t.Errorf("error text = %v", err)
	}
}

func TestSnapshotInterval_ZeroDisables(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	r, clk := snapRouter(t, srv.URL, 0, "web")
	if !r.targets[1].nextSnapshotAt.IsZero() {
		t.Error("nextSnapshotAt scheduled with interval 0")
	}
	before := runtime.NumGoroutine()
	stop := r.startSnapshots()
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines grew %d -> %d with interval 0", before, after)
	}
	clk.Advance(time.Hour)
	stop()
	if n := len(rc.got()); n != 0 {
		t.Fatalf("got %d POSTs with interval 0, want 0", n)
	}
	stopSnapCtr(r)
	got := rc.got()
	if len(got) != 1 || !got[0].ProfileTerminal {
		t.Fatalf("want exactly one terminal POST, got %+v", got)
	}
}

func TestSnapshotJitter(t *testing.T) {
	const interval = 20 * time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		id := fmt.Sprintf("container-%d-%x", i, i*7919)
		j := snapshotJitter(id, interval)
		if j < 0 || j >= interval {
			t.Fatalf("jitter %s out of [0,%s)", j, interval)
		}
		if j != snapshotJitter(id, interval) {
			t.Fatal("jitter not deterministic")
		}
		seen[j/time.Second] = true
	}
	if len(seen) < 15 {
		t.Errorf("jitter hit only %d of 20 one-second buckets; not spreading", len(seen))
	}
	if snapshotJitter("x", 0) != 0 {
		t.Error("jitter with zero interval must be 0")
	}
}

func TestSnapshotTickEvery(t *testing.T) {
	if got := snapshotTickEvery(10 * time.Second); got != time.Second {
		t.Errorf("10s -> %s", got)
	}
	if got := snapshotTickEvery(5 * time.Minute); got != 30*time.Second {
		t.Errorf("5m -> %s", got)
	}
}

func TestSnapshotScheduleStartsWithinInterval(t *testing.T) {
	_, srv := newSnapReceiver(t)
	r, clk := snapRouter(t, srv.URL, 20*time.Second, "web")
	d := r.targets[1].nextSnapshotAt.Sub(clk.Now())
	if d < 0 || d >= 20*time.Second {
		t.Errorf("first snapshot offset %s outside [0,20s)", d)
	}
	if d != snapshotJitter(snapCtr, 20*time.Second) {
		t.Errorf("offset %s != jitter", d)
	}
}

func TestRunSnapshots_PostsCumulativeNonTerminal(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	const interval = 20 * time.Second
	r, clk := snapRouter(t, srv.URL, interval, "web")

	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { r.runSnapshots(ctx, tick); close(done) }()

	files := []string{"/a", "/b", "/c"}
	for i, f := range files {
		r.aggFor(1).RecordFile(f, manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, clk.Now())
		clk.Advance(interval) // always past nextSnapshotAt (jitter < interval)
		tick <- clk.Now()
		// An unbuffered send is accepted before the pass; the next send blocks
		// until the previous pass is finished, so wait on the receiver instead.
		deadline := time.Now().Add(5 * time.Second)
		for len(rc.got()) < i+1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		// Time passes without a due container: an extra tick must not post.
		tick <- clk.Now()
	}
	cancel()
	<-done

	got := rc.got()
	if len(got) != 3 {
		t.Fatalf("got %d POSTs, want 3", len(got))
	}
	for i, m := range got {
		if m.ProfileTerminal {
			t.Errorf("post %d is terminal", i)
		}
		if m.ContainerID != got[0].ContainerID || !m.ProfileStart.Equal(got[0].ProfileStart) {
			t.Errorf("post %d changed window identity", i)
		}
		if len(m.Files) != i+1 {
			t.Errorf("post %d has %d files, want %d (cumulative)", i, len(m.Files), i+1)
		}
		if i > 0 && m.ProfileEnd.Before(got[i-1].ProfileEnd) {
			t.Errorf("profile_end went backwards at %d", i)
		}
		if m.ImageRef != "nginx:1" {
			t.Errorf("image ref = %q", m.ImageRef)
		}
	}
}

func TestSnapshotPass_NotDueNotPosted(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	r, clk := snapRouter(t, srv.URL, 20*time.Second, "web")
	// Before start + jitter nothing is posted.
	clk.t = r.targets[1].nextSnapshotAt.Add(-time.Nanosecond)
	r.snapshotPass(context.Background())
	if n := len(rc.got()); n != 0 {
		t.Fatalf("posted %d before due", n)
	}
	clk.Advance(time.Nanosecond)
	r.snapshotPass(context.Background())
	r.snapshotPass(context.Background()) // schedule advanced: not due again
	if n := len(rc.got()); n != 1 {
		t.Fatalf("posted %d, want 1", n)
	}
	clk.Advance(20 * time.Second)
	r.snapshotPass(context.Background())
	if n := len(rc.got()); n != 2 {
		t.Fatalf("posted %d, want 2", n)
	}
}

func TestSnapshotPass_NoBurstAfterStall(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	r, clk := snapRouter(t, srv.URL, 20*time.Second, "web")
	clk.Advance(time.Hour) // many intervals behind
	r.snapshotPass(context.Background())
	r.snapshotPass(context.Background())
	if n := len(rc.got()); n != 1 {
		t.Fatalf("posted %d after stall, want 1 (no catch-up burst)", n)
	}
	if next := r.targets[1].nextSnapshotAt; !next.Equal(clk.Now().Add(20 * time.Second)) {
		t.Errorf("next = %s", next)
	}
}

func TestRunSnapshots_SkipsUnresolvedTargets(t *testing.T) {
	rc, srv := newSnapReceiver(t)

	// 1. Resolver fails at start: unresolved. Never retried live by the loop.
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	res := &fakeResolver{dep: "web", failNow: true}
	r := newRouter(nil, "", srv.URL, "n", res, false)
	r.snapshotInterval, r.now = 20*time.Second, clk.Now
	r.onContainerStart(container.StartInfo{ContainerID: snapCtr, CgroupID: 1, Pod: container.PodMeta{Namespace: "ns", Name: "p"}})
	waitStartResolve(t, r, 1)
	res.setFailing(false) // a live lookup would now succeed; it must not be used
	res.mu.Lock()
	callsBefore := res.calls
	res.mu.Unlock()
	clk.Advance(time.Hour)
	r.snapshotPass(context.Background())

	// 2. Bare pod (resolved, no owner) is never posted.
	res2 := &fakeResolver{dep: ""}
	r2 := newRouter(nil, "", srv.URL, "n", res2, false)
	r2.snapshotInterval, r2.now = 20*time.Second, clk.Now
	r2.onContainerStart(container.StartInfo{ContainerID: snapCtr, CgroupID: 2, Pod: container.PodMeta{Namespace: "ns", Name: "bare"}})
	waitStartResolve(t, r2, 2)
	clk.Advance(time.Hour)
	r2.snapshotPass(context.Background())

	// 3. No pod metadata (manual cgroup mode).
	r3 := newRouter(nil, "", srv.URL, "n", nil, false)
	r3.snapshotInterval, r3.now = 20*time.Second, clk.Now
	r3.onContainerStart(container.StartInfo{ContainerID: snapCtr, CgroupID: 3})
	clk.Advance(time.Hour)
	r3.snapshotPass(context.Background())

	if n := len(rc.got()); n != 0 {
		t.Fatalf("posted %d interim snapshots for unresolved/bare targets, want 0", n)
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.calls != callsBefore {
		t.Errorf("interim path performed a live lookup (%d -> %d calls)", callsBefore, res.calls)
	}
}

func TestSnapshotPass_FailuresRetriedNextTick(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	const interval = 20 * time.Second
	r, clk := snapRouter(t, srv.URL, interval, "web")
	rc.setStatus(http.StatusInternalServerError)
	r.aggFor(1).RecordFile("/a", manifest.SourceDirect, nil, clk.Now())

	clk.Advance(interval)
	r.snapshotPass(context.Background()) // fails
	if r.targets[1].lastFailLog.IsZero() {
		t.Error("failure not recorded")
	}
	first := r.targets[1].lastFailLog
	clk.Advance(interval)
	r.snapshotPass(context.Background()) // fails again; log rate-limited
	if !r.targets[1].lastFailLog.Equal(first) {
		t.Error("failure log not rate-limited within 10m")
	}
	rc.setStatus(http.StatusCreated)
	clk.Advance(interval)
	r.snapshotPass(context.Background()) // recovers on the next tick
	got := rc.got()
	if len(got) != 3 { // bodies are recorded even for failed attempts
		t.Fatalf("receiver saw %d attempts, want 3", len(got))
	}
	// Failures do not stall the schedule: the next attempt is always one
	// interval after the previous scheduled time, i.e. within (now, now+interval].
	if next := r.targets[1].nextSnapshotAt; !next.After(clk.Now()) || next.After(clk.Now().Add(interval)) {
		t.Errorf("next = %s (now %s)", next, clk.Now())
	}
	// The terminal POST is unaffected by earlier failures.
	stopSnapCtr(r)
	got = rc.got()
	if last := got[len(got)-1]; !last.ProfileTerminal || len(last.Files) != 1 {
		t.Errorf("terminal post wrong: terminal=%t files=%d", last.ProfileTerminal, len(last.Files))
	}
}

func TestSnapshotFailureLogAgainAfterTenMinutes(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	r, clk := snapRouter(t, srv.URL, 20*time.Second, "web")
	rc.setStatus(500)
	clk.Advance(time.Minute)
	r.snapshotPass(context.Background())
	first := r.targets[1].lastFailLog
	clk.Advance(11 * time.Minute)
	r.snapshotPass(context.Background())
	if !r.targets[1].lastFailLog.After(first) {
		t.Error("failure not logged again after 10m")
	}
}

// TestStopFlushIsLastPost interleaves an interim POST that is still in flight
// with a container stop: the terminal POST must wait for it and arrive last, and
// no interim POST may start after the stop.
func TestStopFlushIsLastPost(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	const interval = 20 * time.Second
	r, clk := snapRouter(t, srv.URL, interval, "web")
	gate := make(chan struct{})
	rc.mu.Lock()
	rc.gate = gate
	rc.mu.Unlock()

	clk.Advance(interval)
	passDone := make(chan struct{})
	go func() { r.snapshotPass(context.Background()); close(passDone) }()
	<-rc.hit // interim POST is now in flight at the receiver

	stopDone := make(chan struct{})
	go func() { stopSnapCtr(r); close(stopDone) }()

	select {
	case <-rc.hit:
		t.Fatal("terminal POST sent while interim POST still in flight")
	case <-stopDone:
		t.Fatal("stop completed while interim POST still in flight")
	case <-time.After(150 * time.Millisecond):
	}
	close(gate)
	<-passDone
	<-stopDone

	got := rc.got()
	if len(got) != 2 || got[0].ProfileTerminal || !got[1].ProfileTerminal {
		t.Fatalf("want [interim, terminal], got %d posts: %+v", len(got), got)
	}
	if got[1].ProfileEnd.Before(got[0].ProfileEnd) {
		t.Error("terminal profile_end earlier than interim")
	}

	// A candidate collected before the stop but posted after it is dropped.
	c := snapshotCandidate{agg: r.aggFor(1), target: &postTarget{closed: true, pod: container.PodMeta{Namespace: "ns", Name: "p"}}, dep: "web"}
	r.postInterim(context.Background(), c, clk.Now())
	clk.Advance(time.Hour)
	r.snapshotPass(context.Background())
	if n := len(rc.got()); n != 2 {
		t.Fatalf("interim POST after terminal: %d posts", n)
	}
}

// TestSnapshotRace hammers ticks, stop and events concurrently; its value is
// under -race. Whatever the interleaving, the terminal POST is last and unique.
func TestSnapshotRace(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	const interval = 10 * time.Second
	r, clk := snapRouter(t, srv.URL, interval, "web")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			clk.Advance(interval)
			r.snapshotPass(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; ctx.Err() == nil; i++ {
			if agg := r.aggFor(1); agg != nil {
				agg.RecordFile("/f", manifest.SourceDirect, nil, time.Now())
			}
			runtime.Gosched()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	stopSnapCtr(r)
	cancel()
	wg.Wait()

	got := rc.got()
	terminals := 0
	for i, m := range got {
		if m.ProfileTerminal {
			terminals++
			if i != len(got)-1 {
				t.Errorf("terminal POST at %d of %d, not last", i, len(got))
			}
		}
	}
	if terminals != 1 {
		t.Fatalf("terminal POSTs = %d, want 1", terminals)
	}
}

func TestStartSnapshots_StopWaitsAndPrecedesFlushAll(t *testing.T) {
	rc, srv := newSnapReceiver(t)
	r, _ := snapRouter(t, srv.URL, 10*time.Second, "web")
	stop := r.startSnapshots()
	stop() // must return promptly and be idempotent-safe w.r.t. flushAll
	r.flushAll()
	got := rc.got()
	if len(got) != 1 || got[0].ProfileTerminal {
		t.Fatalf("want one non-terminal shutdown flush, got %+v", got)
	}
	if n := len(rc.got()); n != 1 {
		t.Fatalf("extra posts after flushAll: %d", n)
	}
}

func TestSnapshotDoesNotWriteProfileDir(t *testing.T) {
	_, srv := newSnapReceiver(t)
	dir := t.TempDir()
	r, clk := snapRouter(t, srv.URL, 10*time.Second, "web")
	r.profileDir = dir
	clk.Advance(time.Minute)
	r.snapshotPass(context.Background())
	if ents, _ := readDir(dir); len(ents) != 0 {
		t.Errorf("interim snapshot wrote to profile dir: %v", ents)
	}
}

func readDir(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names, err
}
