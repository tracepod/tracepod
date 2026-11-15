//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/internal/sensor"
	"github.com/tracepod/tracepod/manifest"
)

// countingAllower records AllowCgroup/DenyCgroup calls.
type countingAllower struct {
	allowed []uint64
	denied  []uint64
}

func (a *countingAllower) AllowCgroup(id uint64) error { a.allowed = append(a.allowed, id); return nil }
func (a *countingAllower) DenyCgroup(id uint64) error  { a.denied = append(a.denied, id); return nil }

func mustScope(t *testing.T, include, exclude string) *sensor.NamespaceScope {
	t.Helper()
	s, err := sensor.NewNamespaceScope(include, exclude)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// scopedSensor wires a real NRI plugin to a router the way main does, with both
// a profile directory and a controller URL so either output path would show up.
func scopedSensor(t *testing.T, scope *sensor.NamespaceScope, controllerURL string, res sensor.WorkloadResolver) (*container.Plugin, *cgroupRouter, *countingAllower, string) {
	t.Helper()
	dir := t.TempDir()
	r := newRouter(nil, dir, controllerURL, "node-1", res, false)
	r.scope = scope
	allower := &countingAllower{}
	p := container.NewPlugin(allower, r.onContainerStart, r.onContainerStop)
	p.SetNamespaceFilter(scope.Allows)
	return p, r, allower, dir
}

// runContainer drives CreateContainer → StartContainer → StopContainer for one
// container of pod ns/name. cgroupsPath "/" resolves to the cgroup root, which
// always exists.
func runContainer(t *testing.T, p *container.Plugin, id, ns, name string) {
	t.Helper()
	pod := &api.PodSandbox{Id: "sb-" + id, Namespace: ns, Name: name}
	ctr := &api.Container{Id: id, PodSandboxId: pod.Id, Linux: &api.LinuxContainer{CgroupsPath: "/"}}
	ctx := context.Background()
	if _, _, err := p.CreateContainer(ctx, pod, ctr); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if err := p.StartContainer(ctx, pod, ctr); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if _, err := p.StopContainer(ctx, pod, ctr); err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
}

func profileFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*", "files.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// An excluded container is never allowlisted in-kernel, never resolved, never
// POSTed and never written to the profile directory.
func TestNamespaceScope_ExcludedContainerNeverPostedOrWritten(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "coredns", image: "coredns:1.11"}
	p, r, allower, dir := scopedSensor(t, mustScope(t, "", "kube-system"), srv.URL, res)

	runContainer(t, p, "ctr-ks000000000000000000000000000000000000000000000000000000000", "kube-system", "coredns-abc")

	if len(allower.allowed) != 0 {
		t.Errorf("AllowCgroup called %d times for an excluded container", len(allower.allowed))
	}
	if n := len(r.aggs); n != 0 {
		t.Errorf("router tracks %d aggregators, want 0", n)
	}
	mu.Lock()
	n := len(*got)
	mu.Unlock()
	if n != 0 {
		t.Errorf("got %d POSTs for an excluded container, want 0", n)
	}
	if f := profileFiles(t, dir); len(f) != 0 {
		t.Errorf("profile files written for an excluded container: %v", f)
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.calls != 0 {
		t.Errorf("workload resolver called %d times for an excluded container", res.calls)
	}
}

// Containers outside a non-empty include list are skipped; those inside it are
// profiled as before (one POST and one profile file).
func TestNamespaceScope_IncludeListProfilesOnlyListed(t *testing.T) {
	srv, got, mu := postCapture(t)
	res := &fakeResolver{dep: "web", image: "nginx:1.25"}
	p, _, allower, dir := scopedSensor(t, mustScope(t, "shop,team-*", ""), srv.URL, res)

	runContainer(t, p, "ctr-other00000000000000000000000000000000000000000000000000000", "other", "web-1")
	if len(allower.allowed) != 0 {
		t.Fatalf("AllowCgroup called for a namespace outside the include list")
	}

	runContainer(t, p, "ctr-team000000000000000000000000000000000000000000000000000000", "team-a", "web-2")
	if len(allower.allowed) != 1 {
		t.Fatalf("AllowCgroup calls = %d, want 1 (team-a matches team-*)", len(allower.allowed))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 || (*got)[0].path != "/internal/profiles/team-a/web" {
		t.Errorf("POSTs = %+v, want exactly one for team-a/web", *got)
	}
	if f := profileFiles(t, dir); len(f) != 1 {
		t.Errorf("profile files = %v, want exactly one", f)
	}
}

// The router drops a profile whose namespace becomes known only at stop and is
// out of scope: nothing is written or POSTed.
func TestNamespaceScope_FlushDropsOutOfScopeKnownAtStop(t *testing.T) {
	srv, got, mu := postCapture(t)
	dir := t.TempDir()
	r := newRouter(nil, dir, srv.URL, "node-1", &fakeResolver{dep: "x"}, false)
	r.scope = mustScope(t, "", "kube-system")

	id := "ctr-late00000000000000000000000000000000000000000000000000000000"
	r.onContainerStart(container.StartInfo{ContainerID: id, CgroupID: 77})
	if agg := r.aggFor(77); agg == nil {
		t.Fatal("container with unknown namespace must be tracked when only excludes are set")
	} else {
		agg.RecordFile("/bin/sh", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessExecute}, time.Now())
	}
	r.onContainerStop(id, 77, container.PodMeta{Namespace: "kube-system", Name: "late"})

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 0 {
		t.Errorf("got %d POSTs, want 0", len(*got))
	}
	if _, err := os.Stat(filepath.Join(dir, id)); !os.IsNotExist(err) {
		t.Errorf("profile directory written for an out-of-scope container (err=%v)", err)
	}
}

// --cgroup-path has no namespace: the manual cgroup is traced whatever the
// scope, even with an include list set.
func TestNamespaceScope_ManualCgroupAlwaysTraced(t *testing.T) {
	r := newRouter(nil, t.TempDir(), "", "", nil, false)
	r.scope = mustScope(t, "shop", "kube-system")
	allower := &recordingManualAllower{}

	id, err := registerManualCgroup(r, allower, t.TempDir())
	if err != nil {
		t.Fatalf("registerManualCgroup: %v", err)
	}
	if r.aggFor(id) == nil || len(allower.allowed) != 1 {
		t.Fatal("manual cgroup must be tracked and allowlisted regardless of namespace scope")
	}
}
