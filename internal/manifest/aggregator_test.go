package manifest_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/manifest"
)

func TestAggregator_RecordFile_deduplicates(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "nginx:1.25")
	now := time.Now()

	a.RecordFile("/etc/nginx/nginx.conf", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	a.RecordFile("/etc/nginx/nginx.conf", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now.Add(time.Second))

	m := a.Snapshot()
	if len(m.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(m.Files))
	}
	entry := m.Files["/etc/nginx/nginx.conf"]
	if entry.Count != 2 {
		t.Errorf("count: want 2, got %d", entry.Count)
	}
}

func TestAggregator_RecordFile_firstLastSeen(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	t1 := time.Now()
	t2 := t1.Add(5 * time.Second)

	a.RecordFile("/usr/sbin/nginx", manifest.SourceDirect, nil, t1)
	a.RecordFile("/usr/sbin/nginx", manifest.SourceDirect, nil, t2)

	entry := a.Snapshot().Files["/usr/sbin/nginx"]
	if !entry.FirstSeen.Equal(t1.UTC()) {
		t.Errorf("FirstSeen: want %v, got %v", t1.UTC(), entry.FirstSeen)
	}
	if !entry.LastSeen.Equal(t2.UTC()) {
		t.Errorf("LastSeen: want %v, got %v", t2.UTC(), entry.LastSeen)
	}
}

func TestAggregator_RecordFile_mergesAccessModes(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordFile("/data/db", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	a.RecordFile("/data/db", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessWrite}, now.Add(time.Second))

	entry := a.Snapshot().Files["/data/db"]
	modes := entry.AccessModes
	if len(modes) != 2 {
		t.Fatalf("want 2 access modes, got %d: %v", len(modes), modes)
	}
	if modes[0] != manifest.AccessRead || modes[1] != manifest.AccessWrite {
		t.Errorf("want [r w], got %v", modes)
	}
}

func TestAggregator_RecordFile_accessModesDeduped(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	// Record the same mode three times
	a.RecordFile("/etc/hosts", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	a.RecordFile("/etc/hosts", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now.Add(time.Second))

	entry := a.Snapshot().Files["/etc/hosts"]
	if len(entry.AccessModes) != 1 {
		t.Errorf("want 1 deduplicated mode, got %d: %v", len(entry.AccessModes), entry.AccessModes)
	}
}

func TestAggregator_RecordInferredELF_countIsZero(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordFile("/usr/sbin/nginx", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	a.RecordInferredELF("/lib/x86_64-linux-gnu/libc.so.6", "/usr/sbin/nginx", now)

	m := a.Snapshot()
	entry := m.Files["/lib/x86_64-linux-gnu/libc.so.6"]
	if entry.Source != manifest.SourceInferredELF {
		t.Errorf("source: want %q, got %q", manifest.SourceInferredELF, entry.Source)
	}
	if entry.Count != 0 {
		t.Errorf("count: want 0 for inferred-elf, got %d", entry.Count)
	}
	if entry.InferredFrom != "/usr/sbin/nginx" {
		t.Errorf("inferred_from: want /usr/sbin/nginx, got %q", entry.InferredFrom)
	}
}

func TestAggregator_RecordInferredELF_doesNotOverwriteDirect(t *testing.T) {
	// If a file is directly observed AND inferred as an ELF dep, direct wins.
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordFile("/lib/libc.so.6", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	a.RecordInferredELF("/lib/libc.so.6", "/some/binary", now)

	entry := a.Snapshot().Files["/lib/libc.so.6"]
	if entry.Source != manifest.SourceDirect {
		t.Errorf("direct observation should not be overwritten by inferred-elf")
	}
}

func TestAggregator_Snapshot_containsMetadata(t *testing.T) {
	a := manifest.NewAggregator("abc123", "nginx:1.25")
	m := a.Snapshot()

	if m.SchemaVersion != "1" {
		t.Errorf("schema_version: want %q, got %q", "1", m.SchemaVersion)
	}
	if m.ContainerID != "abc123" {
		t.Errorf("container_id: want %q, got %q", "abc123", m.ContainerID)
	}
	if m.ImageRef != "nginx:1.25" {
		t.Errorf("image_ref: want %q, got %q", "nginx:1.25", m.ImageRef)
	}
	if m.ProfileStart.IsZero() {
		t.Error("profile_start must not be zero")
	}
	if m.ProfileEnd.IsZero() {
		t.Error("profile_end must not be zero")
	}
	if !m.ProfileEnd.After(m.ProfileStart) && !m.ProfileEnd.Equal(m.ProfileStart) {
		t.Errorf("profile_end %v must not be before profile_start %v", m.ProfileEnd, m.ProfileStart)
	}
}

func TestAggregator_Snapshot_doesNotShareState(t *testing.T) {
	// Mutating the returned map must not affect the aggregator.
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()
	a.RecordFile("/etc/hosts", manifest.SourceDirect, nil, now)

	m := a.Snapshot()
	delete(m.Files, "/etc/hosts")

	m2 := a.Snapshot()
	if _, ok := m2.Files["/etc/hosts"]; !ok {
		t.Error("deleting from snapshot should not remove entry from aggregator")
	}
}

func TestAggregator_WriteJSON_validJSON(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "redis:7")
	a.RecordFile("/usr/bin/redis-server", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead, manifest.AccessExecute}, time.Now())
	a.RecordInferredELF("/lib/libc.so.6", "/usr/bin/redis-server", time.Now())

	var buf strings.Builder
	if err := a.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	s := buf.String()
	for _, want := range []string{
		`"schema_version": "1"`,
		`"container_id": "ctr1"`,
		`"image_ref": "redis:7"`,
		`"/usr/bin/redis-server"`,
		`"source": "direct"`,
		`"/lib/libc.so.6"`,
		`"source": "inferred-elf"`,
		`"inferred_from": "/usr/bin/redis-server"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("WriteJSON output missing %q\nfull output:\n%s", want, s)
		}
	}
}

func TestAggregator_RecordDirectoryInclusion_setsFields(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordDirectoryInclusion("/etc/ssl/certs", "/etc/ssl", now)

	m := a.Snapshot()
	entry, ok := m.Files["/etc/ssl/certs"]
	if !ok {
		t.Fatal("expected /etc/ssl/certs to be present")
	}
	if entry.Source != manifest.SourceDirectoryInclusion {
		t.Errorf("source: want %q, got %q", manifest.SourceDirectoryInclusion, entry.Source)
	}
	if entry.IncludedBecause != "/etc/ssl" {
		t.Errorf("included_because: want %q, got %q", "/etc/ssl", entry.IncludedBecause)
	}
	if entry.Count != 0 {
		t.Errorf("count: want 0, got %d", entry.Count)
	}
}

func TestAggregator_RecordDirectoryInclusion_skipsExisting(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	// First record the file via direct observation.
	a.RecordFile("/etc/hosts", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, now)
	// Then try to add it via directory inclusion — must be skipped.
	a.RecordDirectoryInclusion("/etc/hosts", "/etc", now)

	entry := a.Snapshot().Files["/etc/hosts"]
	if entry.Source != manifest.SourceDirect {
		t.Errorf("direct observation should not be replaced by directory inclusion, got source %q", entry.Source)
	}
}

func TestAggregator_MergeAccessModeByBasename_matchesSuffix(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordFile("/lib/x86_64-linux-gnu/libc.so.6", manifest.SourceDirect, nil, now)
	later := now.Add(time.Second)
	a.MergeAccessModeByBasename("libc.so.6", manifest.AccessExecute, later)

	entry := a.Snapshot().Files["/lib/x86_64-linux-gnu/libc.so.6"]
	found := false
	for _, m := range entry.AccessModes {
		if m == manifest.AccessExecute {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AccessExecute to be merged, got %v", entry.AccessModes)
	}
	if !entry.LastSeen.Equal(later.UTC()) {
		t.Errorf("LastSeen: want %v, got %v", later.UTC(), entry.LastSeen)
	}
}

func TestAggregator_MergeAccessModeByBasename_noMatchIsNoop(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	now := time.Now()

	a.RecordFile("/usr/bin/bash", manifest.SourceDirect, nil, now)
	a.MergeAccessModeByBasename("python3", manifest.AccessExecute, now)

	entry := a.Snapshot().Files["/usr/bin/bash"]
	if len(entry.AccessModes) != 0 {
		t.Errorf("no-op expected, but AccessModes changed: %v", entry.AccessModes)
	}
}

func TestAggregator_ConcurrentRecordFile_noRace(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	var wg sync.WaitGroup
	paths := []string{"/etc/hosts", "/etc/passwd", "/usr/bin/ls", "/lib/libc.so.6"}

	for i := 0; i < 100; i++ {
		for _, p := range paths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				a.RecordFile(path, manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, time.Now())
			}(p)
		}
	}
	wg.Wait()

	m := a.Snapshot()
	if len(m.Files) != len(paths) {
		t.Errorf("want %d files, got %d", len(paths), len(m.Files))
	}
	for _, p := range paths {
		entry := m.Files[p]
		if entry.Count != 100 {
			t.Errorf("%s: want count=100, got %d", p, entry.Count)
		}
	}
}

func TestAggregator_ImageRef_survivesSnapshot(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "nginx:1.25-alpine")
	m := a.Snapshot()
	if m.ImageRef != "nginx:1.25-alpine" {
		t.Errorf("ImageRef: got %q, want %q", m.ImageRef, "nginx:1.25-alpine")
	}
}

func TestAggregator_ImageRef_emptyIsEmpty(t *testing.T) {
	a := manifest.NewAggregator("ctr2", "")
	if got := a.Snapshot().ImageRef; got != "" {
		t.Errorf("ImageRef: want empty, got %q", got)
	}
}
