//go:build linux

package container_test

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/tracepod/tracepod/internal/container"
)

// mockAllower implements CgroupAllower and records calls for assertions.
type mockAllower struct {
	allowed []uint64
	denied  []uint64
}

func (m *mockAllower) AllowCgroup(id uint64) error {
	m.allowed = append(m.allowed, id)
	return nil
}

func (m *mockAllower) DenyCgroup(id uint64) error {
	m.denied = append(m.denied, id)
	return nil
}

// makeContainer returns a minimal *api.Container for testing.
// cgroupsPath follows OCI semantics: relative to /sys/fs/cgroup, even when it
// starts with "/". Use "/" to target the cgroup root itself, which always exists.
func makeContainer(id, cgroupsPath string) *api.Container {
	return &api.Container{
		Id:    id,
		Linux: &api.LinuxContainer{CgroupsPath: cgroupsPath},
	}
}

// createAndStart simulates the two-hook sequence containerd fires for a container:
// CreateContainer (before OCI create, cgroup dir absent) then StartContainer
// (after OCI create, cgroup dir present). In tests we use /tmp as a stand-in.
func createAndStart(t *testing.T, p *container.Plugin, ctr *api.Container) {
	t.Helper()
	if _, _, err := p.CreateContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if err := p.StartContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
}

func TestPlugin_StartContainer_allowsCgroupID(t *testing.T) {
	m := &mockAllower{}
	p := container.NewPlugin(m, nil, nil)
	ctr := makeContainer("abc123", "/")

	createAndStart(t, p, ctr)

	if len(m.allowed) != 1 {
		t.Fatalf("expected 1 AllowCgroup call after StartContainer, got %d", len(m.allowed))
	}
	if m.allowed[0] == 0 {
		t.Error("allowed cgroup ID must be non-zero")
	}
}

func TestPlugin_CreateContainer_doesNotAllowYet(t *testing.T) {
	// AllowCgroup must NOT be called at CreateContainer time — the cgroup dir
	// doesn't exist yet in production (OCI runtime hasn't run).
	m := &mockAllower{}
	p := container.NewPlugin(m, nil, nil)
	ctr := makeContainer("abc123", "/")

	if _, _, err := p.CreateContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if len(m.allowed) != 0 {
		t.Errorf("AllowCgroup must not be called during CreateContainer, got %d calls", len(m.allowed))
	}
}

func TestPlugin_StopContainer_deniesCgroupID(t *testing.T) {
	m := &mockAllower{}
	p := container.NewPlugin(m, nil, nil)
	ctr := makeContainer("abc123", "/")

	createAndStart(t, p, ctr)
	_, err := p.StopContainer(context.Background(), nil, ctr)
	if err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	if len(m.denied) != 1 {
		t.Fatalf("expected 1 DenyCgroup call, got %d", len(m.denied))
	}
	if m.denied[0] != m.allowed[0] {
		t.Errorf("denied ID %d != allowed ID %d", m.denied[0], m.allowed[0])
	}
}

func TestPlugin_StopContainer_unknownContainerIsNoop(t *testing.T) {
	m := &mockAllower{}
	p := container.NewPlugin(m, nil, nil)
	ctr := makeContainer("never-seen", "/tmp")

	_, err := p.StopContainer(context.Background(), nil, ctr)
	if err != nil {
		t.Fatalf("StopContainer on unknown container: %v", err)
	}
	if len(m.denied) != 0 {
		t.Errorf("expected no DenyCgroup calls for unknown container, got %d", len(m.denied))
	}
}

func TestPlugin_CreateContainer_noCgroupsPath_isNoop(t *testing.T) {
	m := &mockAllower{}
	p := container.NewPlugin(m, nil, nil)
	ctr := &api.Container{Id: "no-linux", Linux: &api.LinuxContainer{CgroupsPath: ""}}

	if _, _, err := p.CreateContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("CreateContainer with empty CgroupsPath: %v", err)
	}
	if err := p.StartContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("StartContainer with empty CgroupsPath: %v", err)
	}
	if len(m.allowed) != 0 {
		t.Errorf("expected no AllowCgroup call when CgroupsPath is empty, got %d", len(m.allowed))
	}
}

func TestPlugin_StopContainer_podMetaPopulated(t *testing.T) {
	m := &mockAllower{}
	var gotMeta container.PodMeta
	p := container.NewPlugin(m, nil, func(_ string, _ uint64, meta container.PodMeta) {
		gotMeta = meta
	})
	ctr := makeContainer("abc123", "/")
	pod := &api.PodSandbox{
		Namespace:   "mynamespace",
		Name:        "mypod",
		Annotations: map[string]string{"key": "val"},
	}

	createAndStart(t, p, ctr)
	if _, err := p.StopContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("StopContainer: %v", err)
	}

	if gotMeta.Namespace != "mynamespace" {
		t.Errorf("Namespace: want %q, got %q", "mynamespace", gotMeta.Namespace)
	}
	if gotMeta.Name != "mypod" {
		t.Errorf("Name: want %q, got %q", "mypod", gotMeta.Name)
	}
	if gotMeta.Annotations["key"] != "val" {
		t.Errorf("Annotations[key]: want %q, got %q", "val", gotMeta.Annotations["key"])
	}
}

func TestPlugin_StopContainer_nilPodGivesEmptyMeta(t *testing.T) {
	m := &mockAllower{}
	var gotMeta container.PodMeta
	p := container.NewPlugin(m, nil, func(_ string, _ uint64, meta container.PodMeta) {
		gotMeta = meta
	})
	ctr := makeContainer("abc123", "/")

	createAndStart(t, p, ctr)
	if _, err := p.StopContainer(context.Background(), nil, ctr); err != nil {
		t.Fatalf("StopContainer with nil pod: %v", err)
	}

	if gotMeta.Namespace != "" || gotMeta.Name != "" {
		t.Errorf("expected empty PodMeta for nil pod, got %+v", gotMeta)
	}
}

// TestPlugin_NamespaceFilter checks that a container rejected by the namespace
// filter is never allowlisted, never reaches onStart/onStop, and leaves no
// cached state behind (a later in-scope container with the same ID adopts
// normally), for both StartContainer and Synchronize adoption.
func TestPlugin_NamespaceFilter(t *testing.T) {
	m := &mockAllower{}
	var started, stopped int
	p := container.NewPlugin(m,
		func(container.StartInfo) { started++ },
		func(string, uint64, container.PodMeta) { stopped++ })
	p.SetNamespaceFilter(func(ns string) bool { return ns != "kube-system" })

	ctx := context.Background()
	sys := &api.PodSandbox{Id: "sb1", Namespace: "kube-system", Name: "coredns"}
	ctr := &api.Container{Id: "c1", PodSandboxId: "sb1", Linux: &api.LinuxContainer{CgroupsPath: "/"}}
	if _, _, err := p.CreateContainer(ctx, sys, ctr); err != nil {
		t.Fatal(err)
	}
	if err := p.StartContainer(ctx, sys, ctr); err != nil {
		t.Fatal(err)
	}
	if _, err := p.StopContainer(ctx, sys, ctr); err != nil {
		t.Fatal(err)
	}

	running := &api.Container{Id: "c2", PodSandboxId: "sb1", State: api.ContainerState_CONTAINER_RUNNING,
		Linux: &api.LinuxContainer{CgroupsPath: "/"}}
	if _, err := p.Synchronize(ctx, []*api.PodSandbox{sys}, []*api.Container{running}); err != nil {
		t.Fatal(err)
	}

	if len(m.allowed) != 0 || started != 0 || stopped != 0 {
		t.Fatalf("excluded containers: allowed=%d started=%d stopped=%d, want 0/0/0", len(m.allowed), started, stopped)
	}

	// StartContainer reads the namespace from its own sandbox argument when
	// CreateContainer saw none.
	app := &api.PodSandbox{Id: "sb2", Namespace: "shop", Name: "web"}
	ctr3 := &api.Container{Id: "c3", PodSandboxId: "sb2", Linux: &api.LinuxContainer{CgroupsPath: "/"}}
	if _, _, err := p.CreateContainer(ctx, nil, ctr3); err != nil {
		t.Fatal(err)
	}
	if err := p.StartContainer(ctx, app, ctr3); err != nil {
		t.Fatal(err)
	}
	if len(m.allowed) != 1 || started != 1 {
		t.Fatalf("in-scope container: allowed=%d started=%d, want 1/1", len(m.allowed), started)
	}
}
