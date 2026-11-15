//go:build linux

package container

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// TestAdopt_SkippedContainerLeavesNoState: an out-of-scope container's cached
// path and pod metadata are dropped at adoption, since StopContainer returns
// early for containers that were never adopted.
func TestAdopt_SkippedContainerLeavesNoState(t *testing.T) {
	p := NewPlugin(nopAllower{}, nil, nil)
	p.SetNamespaceFilter(func(ns string) bool { return ns != "kube-system" })
	pod := &api.PodSandbox{Id: "sb", Namespace: "kube-system", Name: "x"}
	ctr := &api.Container{Id: "c", PodSandboxId: "sb", Linux: &api.LinuxContainer{CgroupsPath: "/"}}
	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if err := p.StartContainer(context.Background(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if len(p.paths) != 0 || len(p.podMeta) != 0 || len(p.ids) != 0 {
		t.Fatalf("state left behind: paths=%v podMeta=%v ids=%v", p.paths, p.podMeta, p.ids)
	}
}

type nopAllower struct{}

func (nopAllower) AllowCgroup(uint64) error { return nil }
func (nopAllower) DenyCgroup(uint64) error  { return nil }
