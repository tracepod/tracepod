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

	"github.com/tracepod/tracepod/manifest"
)

// Probe manages the BPF kprobe lifecycle.
type Probe struct {
	objs  openatObjects
	links []link.Link
	rd    *ringbuf.Reader
}

// Options configures Open.
type Options struct {
	// RingbufBytes overrides the events ring-buffer size (the BPF map's
	// max_entries, in bytes). Zero keeps the compiled-in default (256 KB). Must
	// be a power of two and a multiple of the page size. A deliberately tiny
	// value is used by the induced-loss test scenario to force
	// bpf_ringbuf_reserve failures under a high-churn workload (schema v3,
	// docs/profile-schema/README.md); it has no production use.
	RingbufBytes uint32

	// TraceStat additionally attaches the vfs_fstatat kprobe, recording
	// stat-family existence checks (access mode "s", schema v4). Off by
	// default: stat volume is far higher than open volume. The schema-v3
	// event-loss counters surface any resulting ring-buffer pressure.
	TraceStat bool
}

// Open loads the BPF program with default options. See OpenWith.
func Open() (*Probe, error) { return OpenWith(Options{}) }

// OpenWith loads the BPF program, attaches three kprobes (do_sys_openat2,
// security_bprm_check, security_mmap_file), and returns a ready Probe.
// The caller must call Close when done.
func OpenWith(opts Options) (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadOpenat()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if opts.RingbufBytes != 0 {
		if m, ok := spec.Maps["events"]; ok {
			m.MaxEntries = opts.RingbufBytes
		}
	}

	var objs openatObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	var links []link.Link
	cleanup := func() {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}

	// Three kprobes always: openat (raw path capture + userspace CWD resolution
	// for relative paths), execve (absolute binary path), mmap PROT_EXEC
	// (basename correlated against openat-recorded full paths). A fourth —
	// vfs_fstatat, existence checks — attaches only when opts.TraceStat is set.
	attachments := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{"do_sys_openat2", objs.KprobeOpenat},
		{"security_bprm_check", objs.KprobeExecve},
		{"security_mmap_file", objs.KprobeMmap},
	}
	if opts.TraceStat {
		attachments = append(attachments, struct {
			symbol string
			prog   *ebpf.Program
		}{"vfs_fstatat", objs.KprobeStat})
	}
	for _, a := range attachments {
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

// lossStatIndex maps each in-kernel loss-counter slot in event_loss_stats to its
// manifest stage name. Indices MUST match the STAT_* defines in openat.c. The
// stage names span both loss classes — bpf_reserve_failed is a HARD loss
// (event_loss.total), path_read_failed is a TOLERATED loss (event_loss.tolerated)
// — but both are counted by the same loss-proof per-CPU mechanism here; the
// sensor's reader routes each to the correct event_loss bucket (see cmd/sensor).
var lossStatIndex = []struct {
	idx   uint32
	stage string
}{
	{0, manifest.LossStageBPFReserveFailed},     // STAT_RESERVE_FAILED   (hard)
	{1, manifest.ToleratedStagePathReadFailed},  // STAT_PATH_READ_FAILED (tolerated)
}

// LossStats reads the in-kernel per-CPU event-loss counters and returns the
// cumulative count per BPF-side stage, summed across all CPUs (schema v3). The
// returned map carries both the hard bpf_reserve_failed counter and the tolerated
// path_read_failed counter; the caller classifies them. The counts are monotonic
// since program load. The sensor's loss reader merges these with its userspace
// counters; see cmd/sensor.
//
// A PERCPU_ARRAY lookup yields one value per possible CPU; we sum them. An error
// here means the BPF stages must be reported not_instrumented for the window
// rather than as a false zero (the caller enforces that).
func (p *Probe) LossStats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(lossStatIndex))
	for _, s := range lossStatIndex {
		var perCPU []uint64
		if err := p.objs.EventLossStats.Lookup(s.idx, &perCPU); err != nil {
			return nil, fmt.Errorf("read event_loss_stats[%d] (%s): %w", s.idx, s.stage, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		out[s.stage] = total
	}
	return out, nil
}
