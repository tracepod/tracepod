//go:build linux

// Package probe loads and manages the openat BPF kprobe.
// Call Open to attach the probe, AllowCgroup/DenyCgroup to control which
// containers are traced, and Close to release all kernel resources.
package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target $BPF_TARGET openat ./openat.c -- -O2 -g -Wall

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)


// Probe manages the BPF kprobe lifecycle.
type Probe struct {
	objs   openatObjects
	links  []link.Link
	rd     *ringbuf.Reader
}

// Open loads the BPF program, attaches fentry/vfs_open and two kprobes
// (security_bprm_check, security_mmap_file), and returns a ready Probe.
// The caller must call Close when done.
func Open() (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs openatObjects
	if err := loadOpenatObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	var links []link.Link
	cleanup := func() {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}

	// fentry/vfs_open — fires after full path resolution; uses bpf_d_path()
	// to capture the absolute path as the container sees it.
	fentryLnk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryVfsOpen,
	})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("attach fentry/vfs_open: %w", err)
	}
	links = append(links, fentryLnk)

	// kprobes for execve and mmap — these remain kprobes because their hook
	// points (security_bprm_check, security_mmap_file) already carry absolute
	// paths and do not need bpf_d_path().
	for _, a := range []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{"security_bprm_check", objs.KprobeExecve},
		{"security_mmap_file", objs.KprobeMmap},
	} {
		lnk, err := link.Kprobe(a.symbol, a.prog, nil)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("attach kprobe/%s: %w", a.symbol, err)
		}
		links = append(links, lnk)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &Probe{objs: objs, links: links, rd: rd}, nil
}

// Reader returns the ring buffer reader. Pass it to ringbuf.New to consume events.
func (p *Probe) Reader() *ringbuf.Reader {
	return p.rd
}

// Close releases all BPF resources in the correct order:
// ring buffer reader → kprobe links → BPF objects.
func (p *Probe) Close() {
	p.rd.Close()
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// AllowCgroup adds a cgroup ID to the in-kernel allowlist. The BPF kprobe
// will emit events for processes running in this cgroup.
// Safe to call concurrently — the BPF map handles synchronisation.
func (p *Probe) AllowCgroup(id uint64) error {
	val := uint8(1)
	if err := p.objs.AllowedCgroups.Put(id, val); err != nil {
		return fmt.Errorf("allow cgroup %d: %w", id, err)
	}
	return nil
}

// DenyCgroup removes a cgroup ID from the in-kernel allowlist. Events for
// processes in this cgroup will be discarded by the BPF kprobe.
func (p *Probe) DenyCgroup(id uint64) error {
	if err := p.objs.AllowedCgroups.Delete(id); err != nil {
		return fmt.Errorf("deny cgroup %d: %w", id, err)
	}
	return nil
}
