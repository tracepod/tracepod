//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/manifest"
)

// fakeResolver is a WorkloadResolver whose behaviour can be flipped to "failing"
// mid-test to simulate the pod/ReplicaSet GC that races StopContainer (OSS-5).
type fakeResolver struct {
	mu      sync.Mutex
	failNow bool
	dep     string
	image   string
	calls   int
}

func (f *fakeResolver) ResolveWorkload(_ context.Context, ns, pod string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNow {
		return "", "", fmt.Errorf("get pod %s/%s: pods %q not found (GC)", ns, pod, pod)
	}
	return f.dep, f.image, nil
}

func (f *fakeResolver) setFailing(v bool) {
	f.mu.Lock()
	f.failNow = v
	f.mu.Unlock()
}

type capturedPost struct {
	path  string
	query string
	body  string
}

// postCapture returns an httptest controller that records every ingest POST.
func postCapture(t *testing.T) (*httptest.Server, *[]capturedPost, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var got []capturedPost
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, capturedPost{path: r.URL.Path, query: r.URL.RawQuery, body: string(b)})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &mu
}

// TestStopLoss_StartResolveSurvivesGC is the OSS-5 regression: a fully-observed
// container whose pod/ReplicaSet are GC'd by the time it stops must STILL land its
// final generation, because the owning workload was resolved and cached at start.
func TestStopLoss_StartResolveSurvivesGC(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "web", image: "nginx:1.25"}
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-abc0000000000000000000000000000000000000000000000000000000000",
		CgroupID:    42,
		Pod:         container.PodMeta{Namespace: "ns1", Name: "web-xyz"},
	})
	// Record an observation that must survive into the merged profile.
	if agg := r.aggFor(42); agg != nil {
		agg.RecordFile("/app/server", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessExecute}, time.Now())
	} else {
		t.Fatal("aggregator missing after start")
	}

	// The pod and its ReplicaSet are now being garbage-collected: a LIVE resolve at
	// stop would 404 (this is exactly the pre-fix loss boundary).
	res.setFailing(true)

	r.onContainerStop("ctr-abc0000000000000000000000000000000000000000000000000000000000", 42, container.PodMeta{Namespace: "ns1", Name: "web-xyz"})

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("expected exactly 1 POST (final generation), got %d", len(*got))
	}
	p := (*got)[0]
	if p.path != "/internal/profiles/ns1/web" {
		t.Errorf("POST path = %q, want /internal/profiles/ns1/web", p.path)
	}
	if !strings.Contains(p.query, "pod=web-xyz") {
		t.Errorf("POST query = %q, want pod=web-xyz", p.query)
	}
	if !strings.Contains(p.body, "/app/server") {
		t.Errorf("POST body missing observed path /app/server: %s", p.body)
	}
}

// TestStopLoss_FlushAllOnShutdown covers the secondary loss: on SIGTERM the sensor
// must flush every in-flight container, not drop it. Cached start-time resolution
// means the flush POST survives even if the pod is concurrently being GC'd.
func TestStopLoss_FlushAllOnShutdown(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "api", image: "go:1.26"}
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-100000000000000000000000000000000000000000000000000000000000",
		CgroupID:    7,
		Pod:         container.PodMeta{Namespace: "ns2", Name: "api-1"},
	})
	if agg := r.aggFor(7); agg != nil {
		agg.RecordFile("/usr/bin/api", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessExecute}, time.Now())
	}

	res.setFailing(true) // GC racing the shutdown — cache must still carry it.
	r.flushAll()

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("expected 1 flushed POST on shutdown, got %d", len(*got))
	}
	if !strings.Contains((*got)[0].body, "/usr/bin/api") {
		t.Errorf("flushed POST missing observed path: %s", (*got)[0].body)
	}
}

// TestStopLoss_FlushAllClaimsExactlyOnce verifies flushAll and a concurrent stop
// cannot double-flush: whichever removes the container from the maps first wins.
func TestStopLoss_FlushAllClaimsExactlyOnce(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "web", image: "nginx"}
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-x00000000000000000000000000000000000000000000000000000000000", CgroupID: 9,
		Pod: container.PodMeta{Namespace: "ns3", Name: "web-x"},
	})

	r.flushAll()
	// A stop that arrives after flush already claimed the container is a no-op.
	r.onContainerStop("ctr-x00000000000000000000000000000000000000000000000000000000000", 9, container.PodMeta{Namespace: "ns3", Name: "web-x"})

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("expected exactly 1 POST (no double-flush), got %d", len(*got))
	}
}

// TestStopLoss_NoTrackedOwnerSkips confirms a pod with no Deployment/StatefulSet
// owner (resolver returns dep=="") is skipped at stop without error — the cached
// "resolved, no owner" decision avoids a live lookup too.
func TestStopLoss_NoTrackedOwnerSkips(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "", image: "busybox"} // resolves, but no tracked owner
	r := newRouter(nil, "", srv.URL, "node-1", res, false)

	r.onContainerStart(container.StartInfo{
		ContainerID: "ctr-d00000000000000000000000000000000000000000000000000000000000", CgroupID: 3,
		Pod: container.PodMeta{Namespace: "ns4", Name: "daemon-1"},
	})
	res.setFailing(true) // must NOT be consulted at stop; decision was cached.
	r.onContainerStop("ctr-d00000000000000000000000000000000000000000000000000000000000", 3, container.PodMeta{Namespace: "ns4", Name: "daemon-1"})

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 0 {
		t.Fatalf("expected 0 POSTs for untracked owner, got %d", len(*got))
	}
	// Exactly one resolve, at start — never a live lookup at stop.
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.calls != 1 {
		t.Errorf("expected 1 resolve (at start), got %d", res.calls)
	}
}
