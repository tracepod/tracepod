package manifest

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

// Aggregator accumulates file-open events for a single container profiling run.
// It deduplicates by path: repeated opens to the same path increment Count and
// extend LastSeen rather than creating duplicate entries.
//
// Aggregator is safe for concurrent use — RecordFile can be called from the
// ring buffer consumer goroutine while the NRI plugin goroutine may call
// Snapshot or WriteJSON.
type Aggregator struct {
	mu           sync.Mutex
	containerID  string
	imageRef     string
	profileStart time.Time

	// R2 coverage evidence. attachKnown gates ProcessStartObserved — without a
	// recorded attach the marker is always false (toward-false rule).
	attachTime            time.Time
	attachKnown           bool
	processAlreadyRunning bool      // a process was already in the cgroup at attach
	firstExecTime         time.Time // zero until the first exec is observed

	// R3 start-event records, in observation order.
	starts []StartEvent

	files map[string]FileEntry // keyed by absolute path
}

// NewAggregator creates a fresh Aggregator for the given container.
// profileStart is set to now and the container's first start event (R3) is
// recorded at that instant. Call RecordAttach to supply the R2 attach evidence,
// and Snapshot to capture the end time.
func NewAggregator(containerID, imageRef string) *Aggregator {
	now := time.Now().UTC()
	return &Aggregator{
		containerID:  containerID,
		imageRef:     imageRef,
		profileStart: now,
		starts:       []StartEvent{{ContainerID: containerID, Timestamp: now}},
		files:        make(map[string]FileEntry),
	}
}

// RecordAttach records the R2 attach evidence: attachTime is when the sensor
// added the container's cgroup to the BPF allowlist, and processAlreadyRunning
// reports whether a process was already running in that cgroup at attach time
// (read from cgroup.procs). A non-empty cgroup at attach means the workload's
// first exec was dropped in-kernel before the cgroup was allowlisted, so the
// startup race was lost — ProcessStartObserved can never be true in that case.
//
// Safe to call concurrently with RecordFile and Snapshot. The last call wins.
func (a *Aggregator) RecordAttach(attachTime time.Time, processAlreadyRunning bool) {
	a.mu.Lock()
	a.attachTime = attachTime.UTC()
	a.attachKnown = true
	a.processAlreadyRunning = processAlreadyRunning
	a.mu.Unlock()
}

// RecordStart appends an additional witnessed container start (R3). Used when a
// container is restarted in place while its aggregator is still live, so a
// single profile can carry more than one start record. The constructor already
// records the first start, so callers only invoke this for subsequent restarts.
func (a *Aggregator) RecordStart(containerID string, t time.Time) {
	a.mu.Lock()
	a.starts = append(a.starts, StartEvent{ContainerID: containerID, Timestamp: t.UTC()})
	a.mu.Unlock()
}

// SetImageRef stores the OCI image reference for this container profile.
// Called at StopContainer time once the image ref is available from K8s metadata.
// Safe to call concurrently with RecordFile and Snapshot.
func (a *Aggregator) SetImageRef(ref string) {
	a.mu.Lock()
	a.imageRef = ref
	a.mu.Unlock()
}

// RecordFile records a single file-open event. If path already exists in the
// manifest the Count is incremented, LastSeen is updated, and any new AccessModes
// are merged in. t is the observation timestamp; pass time.Now() for live events.
func (a *Aggregator) RecordFile(path string, source ObservationSource, modes []AccessMode, t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// R2: the first exec observed anchors the process-start marker. execve is the
	// only source of AccessExecute, so an execute mode marks an exec event.
	if a.firstExecTime.IsZero() && containsMode(modes, AccessExecute) {
		a.firstExecTime = t.UTC()
	}

	existing, ok := a.files[path]
	if !ok {
		a.files[path] = FileEntry{
			Source:      source,
			AccessModes: dedupeAccessModes(nil, modes),
			FirstSeen:   t.UTC(),
			LastSeen:    t.UTC(),
			Count:       1,
		}
		return
	}

	existing.Count++
	if t.After(existing.LastSeen) {
		existing.LastSeen = t.UTC()
	}
	existing.AccessModes = dedupeAccessModes(existing.AccessModes, modes)
	a.files[path] = existing
}

// RecordInferredELF records a shared library dependency resolved from an ELF binary.
// These entries have count=0 since they were not directly observed.
func (a *Aggregator) RecordInferredELF(path, inferredFrom string, t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.files[path]; ok {
		return // already present (direct observation takes precedence)
	}
	a.files[path] = FileEntry{
		Source:       SourceInferredELF,
		AccessModes:  []AccessMode{},
		FirstSeen:    t.UTC(),
		LastSeen:     t.UTC(),
		Count:        0,
		InferredFrom: inferredFrom,
	}
}

// RecordDirectoryInclusion records a file included via safe-mode directory expansion.
func (a *Aggregator) RecordDirectoryInclusion(path, includedBecause string, t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.files[path]; ok {
		return
	}
	a.files[path] = FileEntry{
		Source:          SourceDirectoryInclusion,
		AccessModes:     []AccessMode{},
		FirstSeen:       t.UTC(),
		LastSeen:        t.UTC(),
		Count:           0,
		IncludedBecause: includedBecause,
	}
}

// MergeAccessModeByBasename merges mode into every existing entry whose path
// ends with "/"+basename. This is used for mmap PROT_EXEC events where the BPF
// probe can only supply the filename component (e.g. "libc.so.6") rather than
// the full path. The full path was already recorded by the openat probe — the
// dynamic linker always opens a file before mapping it.
//
// If no entry matches, the call is a no-op (the file was not observed via openat
// and is therefore not in scope for image minimisation).
func (a *Aggregator) MergeAccessModeByBasename(basename string, mode AccessMode, t time.Time) {
	suffix := "/" + basename
	a.mu.Lock()
	defer a.mu.Unlock()
	for path, entry := range a.files {
		if strings.HasSuffix(path, suffix) || path == basename {
			entry.AccessModes = dedupeAccessModes(entry.AccessModes, []AccessMode{mode})
			if t.After(entry.LastSeen) {
				entry.LastSeen = t.UTC()
			}
			a.files[path] = entry
		}
	}
}

// Snapshot returns a point-in-time copy of the manifest with ProfileEnd set to now.
// The Aggregator continues accumulating after Snapshot is called.
func (a *Aggregator) Snapshot() Manifest {
	a.mu.Lock()
	defer a.mu.Unlock()

	files := make(map[string]FileEntry, len(a.files))
	for k, v := range a.files {
		files[k] = v
	}

	starts := make([]StartEvent, len(a.starts))
	copy(starts, a.starts)

	cov := Coverage{
		ProcessStartObserved: a.processStartObservedLocked(),
		AttachTime:           a.attachTime,
	}
	if !a.firstExecTime.IsZero() {
		fe := a.firstExecTime
		cov.FirstExecTime = &fe
	}

	return Manifest{
		SchemaVersion:   SchemaVersion,
		ContainerID:     a.containerID,
		ImageRef:        a.imageRef,
		ProfileStart:    a.profileStart,
		ProfileEnd:      time.Now().UTC(),
		Coverage:        cov,
		ContainerStarts: starts,
		Files:           files,
	}
}

// processStartObservedLocked computes the R2 marker. Caller must hold a.mu.
//
// Every axis must supply positive evidence; any gap resolves to false. See the
// Coverage.ProcessStartObserved doc for the rationale (toward-false bias).
func (a *Aggregator) processStartObservedLocked() bool {
	switch {
	case !a.attachKnown:
		return false // no attach evidence recorded
	case a.processAlreadyRunning:
		return false // workload already running at attach → first exec was dropped
	case a.firstExecTime.IsZero():
		return false // never observed an exec → nothing anchors "from first exec"
	case !a.attachTime.Before(a.firstExecTime):
		return false // attach did not strictly precede the first observed exec
	default:
		return true
	}
}

// WriteJSON writes the current manifest as indented JSON to w.
func (a *Aggregator) WriteJSON(w io.Writer) error {
	m := a.Snapshot()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// containsMode reports whether modes includes m.
func containsMode(modes []AccessMode, m AccessMode) bool {
	for _, x := range modes {
		if x == m {
			return true
		}
	}
	return false
}

// dedupeAccessModes merges new modes into existing, returning a deduplicated slice.
func dedupeAccessModes(existing, new []AccessMode) []AccessMode {
	seen := make(map[AccessMode]struct{}, len(existing)+len(new))
	for _, m := range existing {
		seen[m] = struct{}{}
	}
	for _, m := range new {
		seen[m] = struct{}{}
	}
	out := make([]AccessMode, 0, len(seen))
	// Emit in deterministic order: r w x l m
	for _, m := range []AccessMode{AccessRead, AccessWrite, AccessExecute, AccessLink, AccessMmap} {
		if _, ok := seen[m]; ok {
			out = append(out, m)
		}
	}
	return out
}
