//go:build linux

package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/container"
)

// slowResolver blocks every ResolveWorkload call for delay before answering.
// It simulates a slow/contended K8s API server, which must never stall the NRI
// hook goroutine: containerd bounds the whole Synchronize handshake to ~2s and
// drops the plugin connection on overrun (the stub then exits the process).
type slowResolver struct {
	delay time.Duration
	dep   string
	image string

	mu    sync.Mutex
	calls int
}

func (s *slowResolver) ResolveWorkload(ctx context.Context, ns, pod string) (string, string, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
	return s.dep, s.image, nil
}

// waitStartResolve blocks until the start-time async workload resolve for the
// given cgroup has settled (success or failure). Tests that flip resolver
// behaviour between start and stop use it to pin the ordering the pre-async
// code guaranteed implicitly.
func waitStartResolve(t *testing.T, r *cgroupRouter, cgroupID uint64) {
	t.Helper()
	r.mu.RLock()
	tgt := r.targets[cgroupID]
	r.mu.RUnlock()
	if tgt == nil {
		t.Fatal("no target registered for cgroup")
	}
	if tgt.resolveDone == nil {
		t.Fatal("no start-time resolve was launched")
	}
	select {
	case <-tgt.resolveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("start-time resolve did not settle within 5s")
	}
}

// TestSyncDeadline_StartHookReturnsImmediately is the regression test for the
// Synchronize-deadline crashloop: onContainerStart is invoked once per
// already-running container inside the NRI Synchronize handshake, so it must
// not block on the K8s resolve. With a resolver stuck for 3s, the hook has to
// return in milliseconds — the pre-fix inline resolve serialised the full
// delay per container and blew containerd's 2s deadline.
func TestSyncDeadline_StartHookReturnsImmediately(t *testing.T) {
	srv, _, _ := postCapture(t)
	res := &slowResolver{delay: 3 * time.Second, dep: "web", image: "nginx"}
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	start := time.Now()
	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-sync000000000000000000000000000000000000000000000000000000",
		CgroupID:    21,
		Pod:         container.PodMeta{Namespace: "ns1", Name: "web-1"},
	})
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("onContainerStart blocked for %v with a slow resolver — Synchronize would exceed containerd's deadline", elapsed)
	}
	// The resolve must still have been launched (and eventually settle).
	waitStartResolve(t, r, 21)
}

// TestSyncDeadline_StopRightAfterStartUsesStartResolve pins the handoff the
// async design must preserve: a container that stops while its start-time
// resolve is still in flight must NOT fall back to a live lookup (the path
// that races GC, OSS-5). The flush path waits for the in-flight resolve and
// posts with its result — the resolver is consulted exactly once.
func TestSyncDeadline_StopRightAfterStartUsesStartResolve(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &slowResolver{delay: 200 * time.Millisecond, dep: "web", image: "nginx:1.25"}
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-race000000000000000000000000000000000000000000000000000000",
		CgroupID:    22,
		Pod:         container.PodMeta{Namespace: "ns1", Name: "web-2"},
	})
	// Stop immediately — the async resolve (200ms) is still in flight.
	r.onContainerStop("ctr-race000000000000000000000000000000000000000000000000000000", 22,
		container.PodMeta{Namespace: "ns1", Name: "web-2"})

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(*got))
	}
	if !strings.Contains((*got)[0].path, "/ns1/web") {
		t.Errorf("POST path = %q, want the start-resolved deployment /ns1/web", (*got)[0].path)
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.calls != 1 {
		t.Errorf("resolver consulted %d times, want exactly 1 (start-time only, no live fallback)", res.calls)
	}
}
