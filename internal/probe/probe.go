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

// Open loads the BPF program, attaches kprobes to do_sys_openat2,
// security_bprm_check, and mmap_region, and returns a ready Probe.
// The caller must call Close when done.
func Open() (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs openatObjects
	if err := loadOpenatObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	// Attach all three kprobes. On failure, clean up everything attached so far.
	type kprobeSpec struct {
		symbol string
		prog   interface{ Close() error }
		lnk    *link.Link
	}

	var links []link.Link
	attach := func(symbol string, prog *ebpf.Program) error {
		lnk, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			return fmt.Errorf("attach kprobe/%s: %w", symbol, err)
		}
		links = append(links, lnk)
		return nil
	}

	attachments := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{"do_sys_openat2", objs.KprobeOpenat},
		{"security_bprm_check", objs.KprobeExecve},
		{"security_mmap_file", objs.KprobeMmap},
	}

	for _, a := range attachments {
		if err := attach(a.symbol, a.prog); err != nil {
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, err
		}
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
