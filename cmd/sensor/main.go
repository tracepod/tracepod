//go:build linux

// Command sensor attaches BPF kprobes to do_sys_openat2, security_bprm_check,
// and security_mmap_file and streams container file-open
// events, aggregating them into per-container file manifests.
//
// On StopContainer (via NRI hook), a JSON manifest is written to:
//
//	profiles/<container-id>/files.json
//
// The manifest records every file opened inside the container with its
// observation source, access modes, first/last seen timestamps, and open count.
// Noisy paths (/proc, /sys, /dev, /tmp, *.log) are filtered before aggregation.
//
// If the NRI socket is unreachable (containerd absent or NRI disabled) the
// sensor warns and continues — useful for bare-metal debugging runs where all
// cgroups are implicitly allowed.
//
// Flags:
//
//	--cgroup-path <path>  manually add a cgroup to the allowlist (debug utility;
//	                      useful when NRI is unavailable, e.g. tracing your own shell)
//	--profile-dir <path>  directory for manifest output (default: profiles)
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
	"syscall"
	"time"

	"github.com/tracepod/tracepod/internal/container"
	"github.com/tracepod/tracepod/manifest"
	"github.com/tracepod/tracepod/internal/probe"
	"github.com/tracepod/tracepod/internal/ringbuf"
	"github.com/tracepod/tracepod/internal/sensor"
)

// version and commit are set at build time via -ldflags:
//
//	-X main.version=v0.1.0 -X main.commit=abc1234
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cgroupPath    := flag.String("cgroup-path", "", "manually allow this cgroup path (debug)")
	profileDir    := flag.String("profile-dir", "profiles", "directory for manifest output")
	controllerURL := flag.String("controller-url", "", "TracePod controller URL for K8s mode (e.g. http://tracepod-controller.tracepod.svc:8080)")
	nodeName      := flag.String("node-name", "", "node name (set via Downward API in DaemonSet)")
	showVersion   := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sensor version %s (commit %s)\n", version, commit)
		os.Exit(0)
	}

	p, err := probe.Open()
	if err != nil {
		log.Fatalf("open probe: %v", err)
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
	router := newRouter(*profileDir, *controllerURL, *nodeName, resolver)

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

	// Closing the ring buffer reader from the signal goroutine unblocks
	// consumer.Run(), which returns nil and lets main exit cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		p.Close()
	}()

	c := ringbuf.New(p.Reader(), router.handle)
	if err := c.Run(); err != nil {
		log.Fatalf("consumer: %v", err)
	}
}

// cgroupRouter maps live cgroup IDs to their per-container aggregators and
// routes ring buffer events to the correct aggregator.
type cgroupRouter struct {
	mu           sync.RWMutex
	aggs         map[uint64]*manifest.Aggregator // cgroupID → aggregator
	ctrToCgroup  map[string]uint64               // containerID → cgroupID (for onStop lookup)
	cgroupFSPath map[uint64]string               // cgroupID → cgroup filesystem path
	denyList     *manifest.DenyList
	profileDir    string
	controllerURL string
	nodeName      string
	resolver      sensor.WorkloadResolver // nil in standalone mode
}

func newRouter(profileDir, controllerURL, nodeName string, resolver sensor.WorkloadResolver) *cgroupRouter {
	return &cgroupRouter{
		aggs:          make(map[uint64]*manifest.Aggregator),
		ctrToCgroup:   make(map[string]uint64),
		cgroupFSPath:  make(map[uint64]string),
		denyList:      manifest.DefaultDenyList(),
		profileDir:    profileDir,
		controllerURL: controllerURL,
		nodeName:      nodeName,
		resolver:      resolver,
	}
}

// onContainerStart is called by the NRI plugin when a container's cgroup ID
// is resolved. A new Aggregator is created for the container.
func (r *cgroupRouter) onContainerStart(containerID string, cgroupID uint64, cgroupFSPath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aggs[cgroupID] = manifest.NewAggregator(containerID, "")
	r.ctrToCgroup[containerID] = cgroupID
	r.cgroupFSPath[cgroupID] = cgroupFSPath
	fmt.Fprintf(os.Stderr, "sensor: aggregator created for container=%s cgroup=%d\n", containerID, cgroupID)
}

// onContainerStop is called by the NRI plugin when a container stops.
// It writes the manifest to disk (if --profile-dir is set) and/or POSTs it
// to the controller (if --controller-url is set and the pod has the
// tracepod.io/profile=true annotation).
func (r *cgroupRouter) onContainerStop(containerID string, cgroupID uint64, pod container.PodMeta) {
	r.mu.Lock()
	agg, ok := r.aggs[cgroupID]
	delete(r.aggs, cgroupID)
	delete(r.ctrToCgroup, containerID)
	delete(r.cgroupFSPath, cgroupID)
	r.mu.Unlock()

	if !ok {
		return
	}

	snap := agg.Snapshot()

	// Standalone mode: write to profile directory.
	if r.profileDir != "" {
		dir := filepath.Join(r.profileDir, containerID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "sensor: create profile dir %s: %v\n", dir, err)
		} else {
			outPath := filepath.Join(dir, "files.json")
			f, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sensor: create %s: %v\n", outPath, err)
			} else {
				if err := json.NewEncoder(f).Encode(snap); err != nil {
					fmt.Fprintf(os.Stderr, "sensor: write manifest: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "sensor: manifest written → %s\n", outPath)
				}
				f.Close()
			}
		}
	}

	// K8s mode: resolve deployment + image ref, POST to controller.
	// Filtering is done by the Deployment owner lookup — pods without a Deployment owner are skipped.
	// Note: we do not rely on pod.Annotations because NRI does not guarantee forwarding of
	// Kubernetes pod annotations in all runtime configurations (e.g. kind).
	if r.controllerURL != "" && pod.Namespace != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dep, imageRef, err := r.resolver.ResolveWorkload(ctx, pod.Namespace, pod.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sensor: K8s lookup failed for %s/%s: %v\n", pod.Namespace, pod.Name, err)
			return
		}
		if dep == "" {
			fmt.Fprintf(os.Stderr, "sensor: pod %s/%s has no tracked workload owner (Deployment/StatefulSet) — skipping POST\n", pod.Namespace, pod.Name)
			return
		}
		// Set image ref on aggregator now that we have it from K8s metadata.
		if imageRef != "" {
			agg.SetImageRef(imageRef)
		}
		// Re-snapshot to include the image ref we just set.
		snap = agg.Snapshot()
		if err := sensor.PostProfile(ctx, r.controllerURL, pod.Namespace, dep, pod.Name, r.nodeName, snap); err != nil {
			fmt.Fprintf(os.Stderr, "sensor: POST to controller failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "sensor: profile posted → %s/%s image=%s\n", pod.Namespace, dep, imageRef)
		}
	}
}

// handle is called by the ring buffer consumer for every decoded event.
// It dispatches to the appropriate handler based on the event type.
func (r *cgroupRouter) handle(e ringbuf.Event) {
	switch e.Type {
	case ringbuf.EventTypeOpenat:
		r.handleOpenat(e)
	case ringbuf.EventTypeExecve:
		r.handleExecve(e)
	case ringbuf.EventTypeMmap:
		r.handleMmap(e)
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
	fmt.Printf("pid=%d cgroup=%d comm=%s file=%s\n", e.Pid, e.CgroupID, e.Process(), path)
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
	fmt.Printf("pid=%d cgroup=%d comm=%s exec=%s\n", e.Pid, e.CgroupID, e.Process(), binary)

	// For scripts with a shebang, also record the interpreter.
	interp := r.cleanPath(e.InterpPath())
	if interp != "" && interp != binary {
		agg.RecordFile(interp, manifest.SourceDirect, modes, t)
		fmt.Printf("pid=%d cgroup=%d comm=%s exec-interp=%s\n", e.Pid, e.CgroupID, e.Process(), interp)
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
