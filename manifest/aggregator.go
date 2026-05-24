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

	files map[string]FileEntry // keyed by absolute path
}

// NewAggregator creates a fresh Aggregator for the given container.
// profileStart is set to now; call Snapshot to capture the end time.
func NewAggregator(containerID, imageRef string) *Aggregator {
	return &Aggregator{
		containerID:  containerID,
		imageRef:     imageRef,
		profileStart: time.Now().UTC(),
		files:        make(map[string]FileEntry),
	}
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

	return Manifest{
		SchemaVersion: "1",
		ContainerID:   a.containerID,
		ImageRef:      a.imageRef,
		ProfileStart:  a.profileStart,
		ProfileEnd:    time.Now().UTC(),
		Files:         files,
	}
}

// WriteJSON writes the current manifest as indented JSON to w.
func (a *Aggregator) WriteJSON(w io.Writer) error {
	m := a.Snapshot()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
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
