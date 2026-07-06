//go:build linux

// Command sensor attaches BPF kprobes to do_sys_openat2, security_bprm_check,
// and security_mmap_file and streams container file-open events, aggregating
// them into per-container file manifests.
//
// On StopContainer (via NRI hook), a JSON manifest is written to:
//
//	<profile-dir>/<container-id>/files.json
//
// The manifest records every file opened inside the container with its
// observation source, access modes, first/last seen timestamps, and open count.
// Noisy paths (/proc, /sys, /dev, /tmp, *.log) are filtered before aggregation.
//
// The sensor integrates with containerd via NRI. Only containers started through
// the Kubernetes CRI (kubelet → containerd) are profiled. Containers started
// with docker run or nerdctl run bypass NRI and produce no manifest.
//
// If the NRI socket is unreachable (containerd absent or NRI disabled) the
// sensor warns and continues — useful for bare-metal debugging runs where
// cgroups are added manually via --cgroup-path.
//
// Flags:
//
//	--profile-dir <path>     directory for manifest output (default: profiles)
//	--controller-url <url>   Tracepod controller URL; when set, manifests are POSTed
//	                         to the controller instead of written to --profile-dir
//	                         (e.g. http://tracepod-controller.tracepod.svc:8080)
//	--node-name <name>       node name included in controller POSTs; set automatically
//	                         via the Downward API in DaemonSet deployments
//	--cgroup-path <path>     manually add a cgroup to the allowlist (debug utility;
//	                         useful when NRI is unavailable, e.g. tracing your own shell)
//	--verbose                print every file-open event to stderr (very noisy;
//	                         for debugging only)
//	--version                print version and exit
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/internal/probe"
	"github.com/tracepod/tracepod/internal/ringbuf"
	"github.com/tracepod/tracepod/internal/sensor"
	"github.com/tracepod/tracepod/manifest"
)

// version and commit are set at build time via -ldflags:
//
//	-X main.version=v0.1.0 -X main.commit=abc1234
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cgroupPath := flag.String("cgroup-path", "", "manually allow this cgroup path (debug)")
	profileDir := flag.String("profile-dir", "profiles", "directory for manifest output")
	controllerURL := flag.String("controller-url", "", "TracePod controller URL for K8s mode (e.g. http://tracepod-controller.tracepod.svc:8080)")
	nodeName := flag.String("node-name", "", "node name (set via Downward API in DaemonSet)")
	showVersion := flag.Bool("version", false, "print version and exit")
	verbose := flag.Bool("verbose", false, "print every file-open event to stderr (noisy; for debugging)")
	ringbufBytes := flag.Uint("ringbuf-bytes", 0, "override events ring-buffer size in bytes (0=default 256KB; power of two, page-multiple). Test-only: a tiny value forces event loss for the induced-loss schema-v3 fixture")
	postUnownedNS := flag.String("post-unowned-pods-namespace", "", "POST profiles for pods with no tracked workload owner in this ONE namespace, keyed by pod name (used for the controller's sandbox validation namespace)")
	traceStat := flag.Bool("trace-stat", false, "additionally trace stat-family existence checks (vfs_fstatat kprobe; access mode \"s\", schema v4). Higher event volume — watch event_loss counters")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sensor version %s (commit %s)\n", version, commit)
		os.Exit(0)
	}

	p, err := probe.OpenWith(probe.Options{RingbufBytes: uint32(*ringbufBytes), TraceStat: *traceStat})
	if err != nil {
		log.Fatalf("open probe: %v", err)
	}
	if *ringbufBytes != 0 {
		fmt.Fprintf(os.Stderr, "sensor: events ring buffer overridden to %d bytes (induced-loss test mode)\n", *ringbufBytes)
	}

	// --cgroup-path: manually allow a single cgroup, bypassing NRI.
	if *cgroupPath != "" {
		id, err := container.CgroupIDFromPath(*cgroupPath)
		if err != nil {
			log.Fatalf("resolve --cgroup-path %q: %v", *cgroupPath, err)
		}
		if err := p.AllowCgroup(id); err != nil {
			log.Fatalf("allow cgroup %d: %v", id, err)
		}
		fmt.Fprintf(os.Stderr, "manual cgroup: path=%s id=%d\n", *cgroupPath, id)
	}

	// K8s mode: create a workload resolver when --controller-url is set.
	var resolver sensor.WorkloadResolver
	if *controllerURL != "" {
		r, err := sensor.NewWorkloadResolver()
		if err != nil {
			log.Fatalf("K8s resolver: %v — is --controller-url used outside a cluster?", err)
		}
		resolver = r
	}

	// router dispatches ring buffer events to the right per-container aggregator.
	router := newRouter(p, *profileDir, *controllerURL, *nodeName, resolver, *verbose)
	router.postUnownedNS = *postUnownedNS

	// The consumer must exist before the NRI plugin starts: plugin.Start() runs
	// the Synchronize hook, which adopts already-running containers and creates
	// their aggregators — each aggregator captures an event-loss baseline via
	// router.ReadLoss(), which reads the consumer's decode counter. Wire it now.
	c := ringbuf.New(p.Reader(), router.handle)
	router.consumer = c

	// Connect the NRI plugin so containerd can push container lifecycle events.
	// If NRI is unavailable we warn rather than fatal — the sensor still runs
	// but the allowed_cgroups map stays empty, so no events are emitted.
	plugin := container.NewPlugin(p, router.onContainerStart, router.onContainerStop)
	if err := plugin.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: NRI unavailable (%v) — no containers will be traced\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "NRI connected — waiting for containers.")
		defer plugin.Stop()
	}

	// On SIGINT/SIGTERM, flush every in-flight container profile BEFORE tearing
	// down the probe, so a sensor restart/rollout/node-drain does not silently drop
	// the generation of every currently-tracked container (OSS-5 secondary loss).
	// Closing the ring buffer reader then unblocks consumer.Run(), which returns
	// nil and lets main exit cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "sensor: signal received — flushing in-flight profiles")
		router.flushAll()
		p.Close()
	}()

	if err := c.Run(); err != nil {
		log.Fatalf("consumer: %v", err)
	}
}

// cgroupRouter maps live cgroup IDs to their per-container aggregators and
// routes ring buffer events to the correct aggregator.
//
// It also implements manifest.LossReader: it owns the userspace event-loss
// counter (untrackedCgroup) and reads the BPF-side (probe) and decode-side
// (consumer) counters, so every aggregator can record a per-window event-loss
// delta (schema v3).
type cgroupRouter struct {
	mu            sync.RWMutex
	aggs          map[uint64]*manifest.Aggregator // cgroupID → aggregator
	ctrToCgroup   map[string]uint64               // containerID → cgroupID (for onStop lookup)
	cgroupFSPath  map[uint64]string               // cgroupID → cgroup filesystem path
	targets       map[uint64]*postTarget          // cgroupID → POST destination (resolved at start)
	denyList      *manifest.DenyList
	profileDir    string
	controllerURL string
	nodeName      string
	postUnownedNS string
	resolver      sensor.WorkloadResolver // nil in standalone mode
	verbose       bool

	// Event-loss instrumentation (schema v3).
	probe           *probe.Probe      // BPF-side counters (reserve/read failures)
	consumer        *ringbuf.Consumer // decode_failed counter; set in main before plugin.Start
	untrackedCgroup atomic.Uint64     // events for an allowed cgroup with no live aggregator
}

func newRouter(p *probe.Probe, profileDir, controllerURL, nodeName string, resolver sensor.WorkloadResolver, verbose bool) *cgroupRouter {
	return &cgroupRouter{
		aggs:          make(map[uint64]*manifest.Aggregator),
		ctrToCgroup:   make(map[string]uint64),
		cgroupFSPath:  make(map[uint64]string),
		targets:       make(map[uint64]*postTarget),
		denyList:      manifest.DefaultDenyList(),
		profileDir:    profileDir,
		controllerURL: controllerURL,
		nodeName:      nodeName,
		resolver:      resolver,
		verbose:       verbose,
		probe:         p,
	}
}

// ReadLoss reports the sensor's cumulative, process-wide event-loss counters
// (manifest.LossReader). The in-kernel per-CPU counters span both loss classes —
// the hard bpf_reserve_failed and the tolerated path_read_failed — so it routes
// each by manifest.IsToleratedStage; it then adds the consumer's decode failures
// and the router's untracked-cgroup drops (both hard, userspace). If the in-kernel
// counters cannot be read, BOTH BPF-sourced stages are reported not_instrumented
// rather than as a false zero (schema-v3 zero-is-a-claim rule).
func (r *cgroupRouter) ReadLoss() manifest.LossReport {
	by := make(map[string]uint64, len(manifest.LossStages))
	tol := make(map[string]uint64, len(manifest.ToleratedStages))
	var notInstrumented []string

	bpf, err := r.bpfLossStats()
	if err == nil {
		for k, v := range bpf {
			if manifest.IsToleratedStage(k) {
				tol[k] = v
			} else {
				by[k] = v
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "sensor: event_loss BPF counters unreadable (%v) — reporting not_instrumented\n", err)
		// Every BPF-sourced stage (hard and tolerated) is uncountable this read.
		notInstrumented = append(notInstrumented,
			manifest.LossStageBPFReserveFailed, manifest.ToleratedStagePathReadFailed)
	}

	if r.consumer != nil {
		by[manifest.LossStageDecodeFailed] = r.consumer.DecodeFailures()
	} else {
		notInstrumented = append(notInstrumented, manifest.LossStageDecodeFailed)
	}

	by[manifest.LossStageUntrackedCgroup] = r.untrackedCgroup.Load()

	return manifest.LossReport{ByStage: by, Tolerated: tol, NotInstrumented: notInstrumented}
}

// postTarget is the cached destination for a container's profile POST. The
// owning workload is resolved at container START — when the pod and its
// ReplicaSet reliably exist — so the stop/flush path can POST without a live K8s
// lookup that races pod/RS garbage collection (OSS-5 boundary A). pod carries the
// namespace/name needed to address the POST; resolved reports whether the
// start-time lookup completed (deployment may legitimately be "" for an untracked
// owner). Unresolved targets fall back to a best-effort live lookup at stop.
type postTarget struct {
	containerID string
	pod         container.PodMeta

	// deployment/imageRef/resolved are written by resolveWorkloadAsync and read
	// by the flush path, both under the router mutex.
	deployment string
	imageRef   string
	resolved   bool

	// resolveDone is non-nil when a start-time async resolve was launched and is
	// closed when it finishes (success or failure). The flush path waits on it —
	// bounded — before falling back to a live lookup, so a container that stops
	// moments after starting still gets its start-time resolution (OSS-5: the
	// live fallback is the path that races pod/ReplicaSet GC).
	resolveDone chan struct{}
}

// bpfLossStats reads the in-kernel per-CPU loss counters, guarding a nil probe
// (used in unit tests that construct a router without a live BPF object) so the
// reader degrades to not_instrumented rather than panicking.
func (r *cgroupRouter) bpfLossStats() (map[string]uint64, error) {
	if r.probe == nil {
		return nil, fmt.Errorf("no probe")
	}
	return r.probe.LossStats()
}

// onContainerStart is called by the NRI plugin when a container's cgroup ID
// is resolved. A new Aggregator is created for the container, seeded with the
// R2 attach evidence (attach time + whether a process was already running).
//
// In K8s mode it also resolves and caches the owning workload, while the pod and
// ReplicaSet still exist, so the final POST never depends on a live lookup at stop
// time (OSS-5). That resolve is a live K8s API call, so it runs in a background
// goroutine rather than inline: this hook is invoked once per already-running
// container during the NRI Synchronize handshake, which containerd bounds to a ~2s
// deadline. Resolving inline serialised one round-trip per container and blew that
// deadline on busy nodes — containerd then dropped the plugin connection and the NRI
// stub exited the process (silent exit-0 crashloop). The goroutine still starts at
// container START, so it resolves before GC just as OSS-5 requires, while letting
// Synchronize return in milliseconds.
func (r *cgroupRouter) onContainerStart(info container.StartInfo) {
	agg := manifest.NewAggregator(info.ContainerID, "")
	agg.RecordAttach(info.AttachTime, info.ProcessAlreadyRunning)
	// Capture the event-loss baseline at window start so the profile reports loss
	// during THIS window (schema v3). The router is the process-wide LossReader.
	agg.SetLossReader(r)

	target := &postTarget{containerID: info.ContainerID, pod: info.Pod}

	r.mu.Lock()
	r.aggs[info.CgroupID] = agg
	r.ctrToCgroup[info.ContainerID] = info.CgroupID
	r.cgroupFSPath[info.CgroupID] = info.CgroupFSPath
	r.targets[info.CgroupID] = target
	r.mu.Unlock()

	fmt.Fprintf(os.Stderr, "sensor: tracking  container=%s cgroup=%d startObserved=%t\n",
		info.ContainerID[:12], info.CgroupID, !info.ProcessAlreadyRunning)

	// Resolve the owning workload off the NRI hook goroutine (see doc comment). A
	// failure is non-fatal: target.resolved stays false and the stop path retries
	// with a best-effort live lookup (which only then races GC).
	if r.controllerURL != "" && r.resolver != nil && info.Pod.Namespace != "" {
		target.resolveDone = make(chan struct{})
		go r.resolveWorkloadAsync(target, agg, info.Pod)
	}
}

// resolveWorkloadAsync resolves the owning workload for a just-started container
// and records it on the container's postTarget. It writes through the shared
// target pointer (not the cgroup map), so the result reaches the flush path even
// if the container has already stopped — flush waits on target.resolveDone for
// exactly this handoff.
func (r *cgroupRouter) resolveWorkloadAsync(target *postTarget, agg *manifest.Aggregator, pod container.PodMeta) {
	defer close(target.resolveDone)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dep, imageRef, err := r.resolver.ResolveWorkload(ctx, pod.Namespace, pod.Name)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor: start-time workload resolve for %s/%s failed (%v) — will retry at stop\n",
			pod.Namespace, pod.Name, err)
		return
	}

	r.mu.Lock()
	target.deployment = dep
	target.imageRef = imageRef
	target.resolved = true
	r.mu.Unlock()
	if imageRef != "" {
		agg.SetImageRef(imageRef)
	}
}

// onContainerStop is called by the NRI plugin when a container stops.
// It writes the manifest to disk (if --profile-dir is set) and/or POSTs it
// to the controller (if --controller-url is set and the pod has the
// tracepod.io/profile=true annotation).
func (r *cgroupRouter) onContainerStop(containerID string, cgroupID uint64, pod container.PodMeta) {
	r.mu.Lock()
	agg, ok := r.aggs[cgroupID]
	target := r.targets[cgroupID]
	delete(r.aggs, cgroupID)
	delete(r.ctrToCgroup, containerID)
	delete(r.cgroupFSPath, cgroupID)
	delete(r.targets, cgroupID)
	r.mu.Unlock()

	if !ok {
		return
	}

	// Prefer the start-time target (pod metadata captured before GC). Fall back to
	// the NRI-supplied pod and a bare target if start tracking somehow missed it.
	if target == nil {
		target = &postTarget{containerID: containerID, pod: pod}
	}
	if target.pod.Namespace == "" {
		target.pod = pod
	}

	r.flush(agg, target)
}

// flush writes/POSTs a single container's profile. Shared by onContainerStop and
// the SIGTERM flush path (flushAll).
func (r *cgroupRouter) flush(agg *manifest.Aggregator, target *postTarget) {
	snap := agg.Snapshot()

	// Standalone mode: write to profile directory.
	if r.profileDir != "" {
		dir := filepath.Join(r.profileDir, target.containerID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "sensor: create profile dir %s: %v\n", dir, err)
		} else {
			outPath := filepath.Join(dir, "files.json")
			f, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sensor: create %s: %v\n", outPath, err)
			} else {
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(snap); err != nil {
					fmt.Fprintf(os.Stderr, "sensor: write manifest: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "sensor: manifest written → %s\n", outPath)
				}
				f.Close()
			}
		}
	}

	// K8s mode: POST to controller. The owning workload was resolved at container
	// start (target.resolved); we POST from that cache so the stop path never
	// depends on a live K8s lookup that races pod/ReplicaSet GC (OSS-5). Only when
	// start-time resolution did not complete (e.g. a very short-lived container, or
	// a transient API error at start) do we fall back to a best-effort live lookup.
	// Note: we do not rely on pod.Annotations because NRI does not guarantee
	// forwarding of Kubernetes pod annotations in all runtime configurations (e.g. kind).
	if r.controllerURL == "" || target.pod.Namespace == "" {
		return
	}

	// If a start-time resolve is still in flight, wait for it (bounded: its
	// context times out at 10s) rather than racing ahead to the live fallback —
	// the fallback is the path that loses against pod/ReplicaSet GC (OSS-5).
	if target.resolveDone != nil {
		select {
		case <-target.resolveDone:
		case <-time.After(15 * time.Second):
			fmt.Fprintf(os.Stderr, "sensor: start-time resolve for %s/%s did not settle — falling back to live lookup\n",
				target.pod.Namespace, target.pod.Name)
		}
	}

	r.mu.RLock()
	dep, imageRef, resolved := target.deployment, target.imageRef, target.resolved
	r.mu.RUnlock()
	if !resolved {
		if r.resolver == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		d, ir, err := r.resolver.ResolveWorkload(ctx, target.pod.Namespace, target.pod.Name)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sensor: K8s lookup failed for %s/%s: %v\n", target.pod.Namespace, target.pod.Name, err)
			return
		}
		dep, imageRef = d, ir
	}
	if dep == "" {
		// Bare pods (no Deployment/StatefulSet owner) are normally skipped —
		// cron pods and one-offs would pollute the workload list. The single
		// deliberate exception is the controller's sandbox namespace: the
		// validation flow depends on receiving the sandbox pod's profile (by
		// container ID) to compute the missing-file diff, so pods there POST
		// under their own pod name.
		if r.postUnownedNS != "" && target.pod.Namespace == r.postUnownedNS {
			dep = target.pod.Name
		} else {
			fmt.Fprintf(os.Stderr, "sensor: pod %s/%s has no tracked workload owner (Deployment/StatefulSet) — skipping POST\n", target.pod.Namespace, target.pod.Name)
			return
		}
	}
	// Ensure the image ref is on the snapshot.
	if imageRef != "" {
		agg.SetImageRef(imageRef)
		snap = agg.Snapshot()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sensor.PostProfile(ctx, r.controllerURL, target.pod.Namespace, dep, target.pod.Name, r.nodeName, snap); err != nil {
		fmt.Fprintf(os.Stderr, "sensor: POST to controller failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "sensor: profile posted → %s/%s image=%s\n", target.pod.Namespace, dep, imageRef)
	}
}

// flushAll snapshots and POSTs/writes every currently-tracked container. It is
// invoked on SIGTERM/SIGINT so a sensor restart, rollout, or node drain does not
// silently drop the in-flight generation of every running container (OSS-5
// secondary loss). Each container is claimed by deleting it from the maps under
// the lock, so a concurrent onContainerStop cannot double-flush.
func (r *cgroupRouter) flushAll() {
	r.mu.Lock()
	pending := make([]struct {
		agg    *manifest.Aggregator
		target *postTarget
	}, 0, len(r.aggs))
	for cg, agg := range r.aggs {
		target := r.targets[cg]
		if target == nil {
			target = &postTarget{}
		}
		pending = append(pending, struct {
			agg    *manifest.Aggregator
			target *postTarget
		}{agg, target})
		delete(r.aggs, cg)
		delete(r.cgroupFSPath, cg)
		delete(r.targets, cg)
	}
	r.ctrToCgroup = make(map[string]uint64)
	r.mu.Unlock()

	if len(pending) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "sensor: flushing %d in-flight profile(s) on shutdown\n", len(pending))
	for _, p := range pending {
		r.flush(p.agg, p.target)
	}
}

// handle is called by the ring buffer consumer for every decoded event.
// It dispatches to the appropriate handler based on the event type.
func (r *cgroupRouter) handle(e ringbuf.Event) {
	// The kernel only emits events for allowed cgroups, but the BPF allowlist and
	// the userspace aggregator map can briefly disagree (the race window at
	// container start before onContainerStart registers the aggregator, and
	// in-flight events after stop). An event for a cgroup with no live aggregator
	// is a lost observation — count it (untracked_cgroup, schema v3) before any
	// path filtering, so deliberate denylist drops are NOT counted as loss.
	if r.aggFor(e.CgroupID) == nil {
		r.untrackedCgroup.Add(1)
		return
	}
	switch e.Type {
	case ringbuf.EventTypeOpenat:
		r.handleOpenat(e)
	case ringbuf.EventTypeExecve:
		r.handleExecve(e)
	case ringbuf.EventTypeMmap:
		r.handleMmap(e)
	case ringbuf.EventTypeStat:
		r.handleStat(e)
	}
}

// handleOpenat processes an openat event: filters noise and records the file
// access with the appropriate read/write modes.
//
// The kprobe captures the raw user-space path string. Absolute paths are
// passed directly to cleanPath. Relative paths (e.g. "app.rb" opened via
// openat(AT_FDCWD, "app.rb")) are resolved against the process's CWD by
// reading /proc/<pid>/cwd — the process is still inside the syscall when
// the ring buffer event is consumed, so the /proc entry is always valid.
func (r *cgroupRouter) handleOpenat(e ringbuf.Event) {
	raw := e.Path()
	if raw == "" {
		return
	}

	var path string
	if raw[0] == '/' {
		path = r.cleanPath(raw)
	} else {
		r.mu.RLock()
		cgFSPath := r.cgroupFSPath[e.CgroupID]
		r.mu.RUnlock()
		if cwd := cwdForEvent(e.Pid, cgFSPath); cwd != "" {
			path = r.cleanPath(filepath.Join(cwd, raw))
		}
	}
	if path == "" {
		return
	}

	agg := r.aggFor(e.CgroupID)
	if agg == nil {
		return
	}

	modes := accessModesFromFlags(e.FlagsOrProt)
	agg.RecordFile(path, manifest.SourceDirect, modes, time.Now())
	if r.verbose {
		fmt.Fprintf(os.Stderr, "pid=%d cgroup=%d comm=%s file=%s\n", e.Pid, e.CgroupID, e.Process(), path)
	}
}

// handleExecve processes an execve event: records the binary (and script
// interpreter if different) with the execute access mode.
func (r *cgroupRouter) handleExecve(e ringbuf.Event) {
	binary := r.cleanPath(e.Path())
	if binary == "" {
		return
	}

	agg := r.aggFor(e.CgroupID)
	if agg == nil {
		return
	}

	modes := []manifest.AccessMode{manifest.AccessExecute}
	t := time.Now()
	agg.RecordFile(binary, manifest.SourceDirect, modes, t)
	if r.verbose {
		fmt.Fprintf(os.Stderr, "pid=%d cgroup=%d comm=%s exec=%s\n", e.Pid, e.CgroupID, e.Process(), binary)
	}

	// For scripts with a shebang, also record the interpreter.
	interp := r.cleanPath(e.InterpPath())
	if interp != "" && interp != binary {
		agg.RecordFile(interp, manifest.SourceDirect, modes, t)
		if r.verbose {
			fmt.Fprintf(os.Stderr, "pid=%d cgroup=%d comm=%s exec-interp=%s\n", e.Pid, e.CgroupID, e.Process(), interp)
		}
	}
}

// handleStat processes a stat-family existence check (--trace-stat, schema
// v4). Interpreters prove files are required without opening them — CPython
// stats a module's .py source and loads only the cached pyc — so existence
// checks are load-bearing observations. Relative paths resolve via the same
// CWD machinery as openat.
func (r *cgroupRouter) handleStat(e ringbuf.Event) {
	raw := e.Path()
	if raw == "" {
		return
	}

	var path string
	if raw[0] == '/' {
		path = r.cleanPath(raw)
	} else {
		r.mu.RLock()
		cgFSPath := r.cgroupFSPath[e.CgroupID]
		r.mu.RUnlock()
		if cwd := cwdForEvent(e.Pid, cgFSPath); cwd != "" {
			path = r.cleanPath(filepath.Join(cwd, raw))
		}
	}
	if path == "" {
		return
	}

	agg := r.aggFor(e.CgroupID)
	if agg == nil {
		return
	}

	agg.RecordFile(path, manifest.SourceDirect, []manifest.AccessMode{manifest.AccessStat}, time.Now())
	if r.verbose {
		fmt.Fprintf(os.Stderr, "pid=%d cgroup=%d comm=%s stat=%s\n", e.Pid, e.CgroupID, e.Process(), path)
	}
}

// handleMmap processes a mmap PROT_EXEC event. The BPF probe supplies only the
// filename component (e.g. "libc.so.6") — full path resolution via bpf_d_path
// is unavailable in kprobe context. We correlate by suffix against paths already
// recorded by the openat probe: the dynamic linker always opens a file before
// mapping it, so the full path is guaranteed to exist in the aggregator first.
func (r *cgroupRouter) handleMmap(e ringbuf.Event) {
	basename := e.Path()
	if basename == "" {
		return
	}

	agg := r.aggFor(e.CgroupID)
	if agg == nil {
		return
	}

	agg.MergeAccessModeByBasename(basename, manifest.AccessMmap, time.Now())
}

// cwdForEvent resolves the CWD for the process that emitted the given event.
//
// bpf_get_current_pid_tgid() returns PIDs in the kernel's initial (outermost)
// PID namespace. In production Kubernetes (hostPID:true, no nesting), the
// sensor's /proc uses that same namespace and the direct readlink works.
//
// In nested environments (e.g. kind-in-Lima VM), the sensor's /proc shows
// kind-node-level PIDs while BPF reports Lima VM PIDs. The fallback reads
// cgroup.procs from the container's cgroup directory to obtain a local PID,
// then reads /proc/<local_pid>/cwd. cgroupFSPath must be the absolute path to
// the container's cgroup directory under /sys/fs/cgroup; pass "" to skip.
func cwdForEvent(bpfPid uint32, cgroupFSPath string) string {
	// Production fast path: BPF PID is visible in sensor's /proc.
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", bpfPid)); err == nil {
		return cwd
	}
	// Nested-environment fallback: find a local PID from cgroup.procs.
	if cgroupFSPath == "" {
		return ""
	}
	procsFile := cgroupFSPath + "/cgroup.procs"
	data, err := os.ReadFile(procsFile)
	if err != nil {
		return ""
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		localPid, err := strconv.ParseUint(string(line), 10, 32)
		if err != nil {
			continue
		}
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", localPid)); err == nil {
			return cwd
		}
	}
	return ""
}

// cleanPath validates and normalises a kernel-supplied path. Returns "" if the
// path should be discarded (relative, root, or denylist match).
func (r *cgroupRouter) cleanPath(path string) string {
	// kprobe/do_sys_openat2 events may carry relative paths; those are resolved
	// in handleOpenat via /proc/<pid>/cwd before reaching cleanPath.
	// The absolute-path guard here covers the mmap probe (basename-only) and
	// acts as a safety net for any unexpected relative paths.
	if len(path) == 0 || path[0] != '/' {
		return ""
	}
	// Normalise away ".." or "./" components.
	path = filepath.Clean(path)
	if path == "/" || !r.denyList.Allow(path) {
		return ""
	}
	return path
}

// aggFor returns the aggregator for the given cgroup ID, or nil if not tracked.
func (r *cgroupRouter) aggFor(cgroupID uint64) *manifest.Aggregator {
	r.mu.RLock()
	agg, ok := r.aggs[cgroupID]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return agg
}

// accessModesFromFlags converts open_how.flags to an AccessMode slice.
// O_RDONLY (0) → r
// O_WRONLY (1) → w
// O_RDWR   (2) → r, w
// O_APPEND adds w regardless of the access mode bits.
func accessModesFromFlags(flags uint64) []manifest.AccessMode {
	const (
		oRDONLY = 0
		oWRONLY = 1
		oRDWR   = 2
		oAPPEND = 0x400
	)
	accMode := flags & 3
	var modes []manifest.AccessMode
	if accMode == oRDONLY || accMode == oRDWR {
		modes = append(modes, manifest.AccessRead)
	}
	if accMode == oWRONLY || accMode == oRDWR || (flags&oAPPEND != 0) {
		modes = append(modes, manifest.AccessWrite)
	}
	return modes
}
