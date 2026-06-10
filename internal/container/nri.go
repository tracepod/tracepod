//go:build linux

package container

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

// StartInfo carries the per-container attach evidence the onStart callback needs
// for the R2 process-start coverage marker. AttachTime is when the sensor added
// the container's cgroup to the BPF allowlist; ProcessAlreadyRunning reports
// whether a process was already present in the cgroup at that moment (its first
// exec was therefore dropped in-kernel before allowlisting — the startup race
// was lost). Containers adopted via Synchronize (already running when the sensor
// started) always carry ProcessAlreadyRunning=true.
type StartInfo struct {
	ContainerID           string
	CgroupID              uint64
	CgroupFSPath          string
	AttachTime            time.Time
	ProcessAlreadyRunning bool
}

// PodMeta contains the Kubernetes pod metadata available from the NRI PodSandbox
// at StopContainer time. Fields are empty strings/nil when NRI provides no pod
// (e.g. in unit tests that pass nil for the pod parameter).
type PodMeta struct {
	Namespace   string
	Name        string
	Annotations map[string]string
}

// CgroupAllower is implemented by *probe.Probe. It is declared as an interface
// here so the NRI plugin can be unit-tested without a running kernel or BPF maps.
type CgroupAllower interface {
	AllowCgroup(id uint64) error
	DenyCgroup(id uint64) error
}

// Plugin subscribes to containerd's NRI container lifecycle events and updates
// the BPF cgroup allowlist as containers start and stop.
//
// Hook timing:
//
//	CreateContainer  fires before the OCI runtime runs  → cgroup dir does not exist yet
//	StartContainer   fires after OCI create, before OCI start → cgroup dir exists, process not yet running
//	StopContainer    fires after the container process exits
//
// We use CreateContainer only to record the cgroup path from the container spec.
// AllowCgroup is called from StartContainer, which is the earliest point at which
// the cgroup directory is guaranteed to exist.
//
// The optional onStart / onStop callbacks allow the caller (e.g. main) to hook
// container lifecycle events without importing the container package's internals.
// Pass nil for either callback to skip it.
//
// Lifecycle:
//
//	p := container.NewPlugin(probe, onStart, onStop)
//	if err := p.Start(); err != nil { ... }
//	defer p.Stop()
type Plugin struct {
	allower CgroupAllower
	nri     stub.Stub

	// onStart is called after cgroup ID is resolved and AllowCgroup succeeds,
	// with the attach evidence for the R2 coverage marker (see StartInfo).
	onStart func(StartInfo)

	// onStop is called after DenyCgroup. containerID and cgroupID match those
	// provided to the corresponding onStart call. pod carries the Kubernetes
	// metadata for the pod that owned this container.
	onStop func(containerID string, cgroupID uint64, pod PodMeta)

	mu      sync.Mutex
	paths   map[string]string  // containerID → cgroupsPath (from CreateContainer)
	ids     map[string]uint64  // containerID → cgroup ID (from StartContainer)
	podMeta map[string]PodMeta // containerID → pod metadata (cached at CreateContainer)
}

// NewPlugin constructs a Plugin. Call Start to connect to the NRI socket.
// onStart is called after a container's cgroup ID is resolved; onStop is called
// when a container stops with pod metadata from the NRI PodSandbox. Either
// callback may be nil.
func NewPlugin(allower CgroupAllower, onStart func(StartInfo), onStop func(containerID string, cgroupID uint64, pod PodMeta)) *Plugin {
	return &Plugin{
		allower: allower,
		onStart: onStart,
		onStop:  onStop,
		paths:   make(map[string]string),
		ids:     make(map[string]uint64),
		podMeta: make(map[string]PodMeta),
	}
}

// Start connects to the containerd NRI socket and begins receiving container
// lifecycle events. It returns an error if the socket is unreachable.
func (p *Plugin) Start() error {
	s, err := stub.New(p,
		stub.WithPluginName("neeva-sensor"),
		stub.WithPluginIdx("00"),
	)
	if err != nil {
		return fmt.Errorf("create NRI stub: %w", err)
	}
	p.nri = s
	if err := p.nri.Start(context.Background()); err != nil {
		return fmt.Errorf("start NRI stub: %w", err)
	}
	return nil
}

// Stop disconnects from NRI and releases the socket.
func (p *Plugin) Stop() {
	if p.nri != nil {
		p.nri.Stop()
	}
}

// CreateContainer is invoked by NRI before the OCI runtime creates the container.
// The cgroup directory does not exist yet — we only record the path for use in
// StartContainer.
func (p *Plugin) CreateContainer(
	_ context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	cgPath := ctr.GetLinux().GetCgroupsPath()
	fmt.Fprintf(os.Stderr, "sensor: CreateContainer id=%s cgroupsPath=%q\n", ctr.GetId(), cgPath)
	if cgPath == "" {
		return nil, nil, nil
	}
	p.mu.Lock()
	p.paths[ctr.GetId()] = cgPath
	// Cache pod metadata here — NRI reliably provides it at CreateContainer time
	// even when StopContainer may receive a nil or empty pod sandbox.
	if pod.GetNamespace() != "" {
		p.podMeta[ctr.GetId()] = PodMeta{
			Namespace:   pod.GetNamespace(),
			Name:        pod.GetName(),
			Annotations: pod.GetAnnotations(),
		}
	}
	p.mu.Unlock()
	return nil, nil, nil
}

// StartContainer is invoked by NRI after the OCI runtime has created the
// container (cgroup directory now exists) but before the container process
// starts. This is the earliest safe point to resolve the cgroup path to an ID.
func (p *Plugin) StartContainer(
	_ context.Context,
	_ *api.PodSandbox,
	ctr *api.Container,
) error {
	p.mu.Lock()
	cgPath, ok := p.paths[ctr.GetId()]
	p.mu.Unlock()
	if !ok {
		// Container was not seen in CreateContainer (e.g. predated sensor startup).
		fmt.Fprintf(os.Stderr, "sensor: StartContainer id=%s — no path recorded, skipping\n", ctr.GetId())
		return nil
	}

	// Normal start: the sensor attaches before the runtime signals the workload
	// to exec its entrypoint, so it wins the startup race (alreadyRunning=false).
	// resolveCgroupPath turns the raw NRI cgroupsPath (which may be in systemd
	// slice form) into an absolute /sys/fs/cgroup path.
	p.adopt(ctr, resolveCgroupPath(cgPath), false)
	return nil
}

// adopt resolves the cgroup path to an ID, allowlists it, and fires onStart with
// the R2 attach evidence. alreadyRunning is the load-bearing signal for the
// process-start marker and is determined by HOW the sensor learned of the
// container:
//
//   - StartContainer hook (alreadyRunning=false): the sensor attaches at the
//     container's start, before the runtime signals the workload to exec its
//     entrypoint. The cgroup may already hold the pre-exec runc-init process,
//     but the workload's first (entrypoint) exec has NOT happened yet, so the
//     sensor will observe it — the race is won.
//   - Synchronize (alreadyRunning=true): the container was already running when
//     the sensor registered, so its first exec was emitted (and dropped
//     in-kernel) before the sensor attached — the race is lost.
//
// We deliberately do NOT infer alreadyRunning from cgroup.procs: at the
// StartContainer hook the runc-init process is already in the cgroup even though
// the entrypoint has not exec'd, so a cgroup.procs probe would wrongly classify
// every fresh start as a lost race. cgPath must already be resolved to an
// absolute /sys/fs/cgroup path.
func (p *Plugin) adopt(ctr *api.Container, cgPath string, alreadyRunning bool) {
	id, err := CgroupIDFromPath(cgPath)
	if err != nil {
		// Log and continue — don't block the container from starting.
		fmt.Fprintf(os.Stderr, "sensor: adopt id=%s — CgroupIDFromPath(%q) failed: %v\n", ctr.GetId(), cgPath, err)
		return
	}

	p.mu.Lock()
	p.ids[ctr.GetId()] = id
	p.mu.Unlock()

	attachTime := time.Now().UTC()

	if err := p.allower.AllowCgroup(id); err != nil {
		fmt.Fprintf(os.Stderr, "sensor: adopt id=%s — AllowCgroup(%d) failed: %v\n", ctr.GetId(), id, err)
	}

	fmt.Fprintf(os.Stderr, "sensor: adopt id=%s cgroupID=%d alreadyRunning=%t — allowed\n",
		ctr.GetId(), id, alreadyRunning)

	if p.onStart != nil {
		p.onStart(StartInfo{
			ContainerID:           ctr.GetId(),
			CgroupID:              id,
			CgroupFSPath:          cgPath,
			AttachTime:            attachTime,
			ProcessAlreadyRunning: alreadyRunning,
		})
	}
}

// Synchronize is invoked by NRI when the plugin first registers. It receives the
// pods and containers already running on the node. The sensor adopts each
// running container so it produces a profile, but marks every adopted container
// as having lost the startup race (ProcessAlreadyRunning=true) — by definition
// the sensor attached after these containers started, so their first exec was
// never observed. This is the R2 "missed-start" case.
func (p *Plugin) Synchronize(
	_ context.Context,
	pods []*api.PodSandbox,
	ctrs []*api.Container,
) ([]*api.ContainerUpdate, error) {
	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}

	for _, ctr := range ctrs {
		if ctr.GetState() != api.ContainerState_CONTAINER_RUNNING {
			continue
		}
		cgPath := ctr.GetLinux().GetCgroupsPath()
		if cgPath == "" {
			continue
		}
		p.mu.Lock()
		p.paths[ctr.GetId()] = cgPath
		if pod := podByID[ctr.GetPodSandboxId()]; pod != nil && pod.GetNamespace() != "" {
			p.podMeta[ctr.GetId()] = PodMeta{
				Namespace:   pod.GetNamespace(),
				Name:        pod.GetName(),
				Annotations: pod.GetAnnotations(),
			}
		}
		p.mu.Unlock()

		fmt.Fprintf(os.Stderr, "sensor: Synchronize adopting running id=%s\n", ctr.GetId())
		p.adopt(ctr, resolveCgroupPath(cgPath), true)
	}
	return nil, nil
}

// resolveCgroupPath converts a raw NRI cgroupsPath to an absolute filesystem
// path under /sys/fs/cgroup.
//
// Two formats are handled generically:
//
//  1. OCI/cgroupfs format — path relative to the cgroup namespace root:
//     "/kubepods/besteffort/podXXX/containerID"  (already absolute)
//     "kubepods/besteffort/podXXX/containerID"   (relative, prefixed)
//
//  2. Systemd cgroup driver format — used when containerd's SystemdCgroup=true.
//     Produced by kubeadm, kind (containerd ≥ v2.0), EKS AL2023, GKE COS, and
//     any distro that configures the systemd cgroup driver:
//     "kubelet-kubepods-besteffort-podXXX.slice:cri-containerd:containerID"
//     Converted by expanding the slice hierarchy into its filesystem form.
func resolveCgroupPath(raw string) string {
	// Systemd format: "A-B.slice:scope-prefix:scope-suffix"
	if parts := strings.SplitN(raw, ":", 3); len(parts) == 3 && strings.HasSuffix(parts[0], ".slice") {
		return expandSystemdCgroupPath(parts[0], parts[1], parts[2])
	}
	// OCI/cgroupfs format — already a full path or relative to cgroupRoot.
	if strings.HasPrefix(raw, cgroupRoot) {
		return raw
	}
	return cgroupRoot + "/" + strings.TrimPrefix(raw, "/")
}

// expandSystemdCgroupPath converts a systemd-format cgroup location to the
// actual filesystem path under /sys/fs/cgroup.
//
// The systemd cgroup driver encodes a container as:
//
//	<slice>.slice:scope-prefix:container-id
//
// where <slice>.slice expands to a nested hierarchy. For example, the slice
// name "A-B-C-D" maps to the hierarchy A.slice/A-B.slice/A-B-C.slice/A-B-C-D.slice,
// and the container scope becomes scope-prefix-container-id.scope.
//
// Example:
//
//	"kubelet-kubepods-besteffort-podXXX.slice:cri-containerd:containerID"
//
// expands to:
//
//	/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/
//	  kubelet-kubepods-besteffort.slice/
//	  kubelet-kubepods-besteffort-podXXX.slice/
//	  cri-containerd-containerID.scope
func expandSystemdCgroupPath(sliceWithExt, scopePrefix, scopeSuffix string) string {
	sliceName := strings.TrimSuffix(sliceWithExt, ".slice")
	components := strings.Split(sliceName, "-")
	parts := make([]string, 0, 1+len(components)+1)
	parts = append(parts, cgroupRoot)
	for i := range components {
		parts = append(parts, strings.Join(components[:i+1], "-")+".slice")
	}
	parts = append(parts, scopePrefix+"-"+scopeSuffix+".scope")
	return strings.Join(parts, "/")
}

// StopContainer is invoked by NRI when a container stops. It removes the
// container's cgroup ID from the BPF allowlist.
func (p *Plugin) StopContainer(
	_ context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) ([]*api.ContainerUpdate, error) {
	p.mu.Lock()
	id, ok := p.ids[ctr.GetId()]
	delete(p.paths, ctr.GetId())
	delete(p.ids, ctr.GetId())
	p.mu.Unlock()

	if !ok {
		// Container was never started through this plugin instance.
		return nil, nil
	}

	fmt.Fprintf(os.Stderr, "sensor: StopContainer id=%s cgroupID=%d ns=%q name=%q — denying\n",
		ctr.GetId(), id, pod.GetNamespace(), pod.GetName())

	if err := p.allower.DenyCgroup(id); err != nil {
		fmt.Fprintf(os.Stderr, "sensor: StopContainer id=%s — DenyCgroup(%d) failed: %v\n", ctr.GetId(), id, err)
	}

	if p.onStop != nil {
		// pod.Get*() are nil-safe protobuf generated methods — return "" when pod is nil.
		// Fall back to cached metadata if NRI doesn't provide pod info at stop time.
		ns := pod.GetNamespace()
		name := pod.GetName()
		if ns == "" {
			if cached, ok := p.podMeta[ctr.GetId()]; ok {
				ns = cached.Namespace
				name = cached.Name
			}
		}
		meta := PodMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: pod.GetAnnotations(),
		}
		p.onStop(ctr.GetId(), id, meta)
	}
	delete(p.podMeta, ctr.GetId())
	return nil, nil
}
