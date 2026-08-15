package manifest_test

import (
	"testing"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// TestAdoptionMode_StartAnchored pins the trust boundary. Only a mode that
// demonstrably attaches before the workload can exec is start-anchored;
// everything else — including the zero value every pre-v5 profile carries — is
// untrusted. New discovery mechanisms must opt in explicitly rather than
// inherit trust by omission.
func TestAdoptionMode_StartAnchored(t *testing.T) {
	cases := map[manifest.AdoptionMode]bool{
		manifest.AdoptionNRIStart: true,
		manifest.AdoptionNRISync:  false,
		manifest.AdoptionUnknown:  false,
		"some-future-mechanism":   false,
	}
	for mode, want := range cases {
		if got := mode.StartAnchored(); got != want {
			t.Errorf("AdoptionMode(%q).StartAnchored() = %v, want %v", mode, got, want)
		}
	}
}

func TestAggregator_RecordAdoptionMode(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")

	// Unset is the untrusted default.
	if got := a.Snapshot().Coverage.AdoptionMode; got != manifest.AdoptionUnknown {
		t.Errorf("unset AdoptionMode = %q, want empty", got)
	}

	a.RecordAdoptionMode(manifest.AdoptionNRIStart)
	if got := a.Snapshot().Coverage.AdoptionMode; got != manifest.AdoptionNRIStart {
		t.Errorf("AdoptionMode = %q, want %q", got, manifest.AdoptionNRIStart)
	}
}

// TestSnapshotTerminality is the guard that makes a truncated window
// distinguishable from a complete one. Snapshot is explicitly non-terminal and
// the aggregator keeps accumulating afterwards, so without the flag a mid-life
// capture is indistinguishable on the wire from a finished profile — and it has
// FEWER files, so it reads as cleaner rather than broken.
func TestSnapshotTerminality(t *testing.T) {
	a := manifest.NewAggregator("ctr1", "")
	a.RecordFile("/etc/hosts", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, time.Now())

	if a.Snapshot().ProfileTerminal {
		t.Error("Snapshot must be non-terminal — the window may still be open")
	}
	if !a.SnapshotFinal().ProfileTerminal {
		t.Error("SnapshotFinal must be terminal")
	}

	// The aggregator keeps accumulating after a non-terminal snapshot; that is
	// exactly why the flag has to exist.
	before := len(a.Snapshot().Files)
	a.RecordFile("/etc/resolv.conf", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, time.Now())
	if after := len(a.Snapshot().Files); after != before+1 {
		t.Errorf("aggregator stopped accumulating after Snapshot: %d → %d", before, after)
	}
}

// TestSnapshotFinal_PreservesEverythingElse guards against SnapshotFinal
// drifting from Snapshot beyond the one flag.
func TestSnapshotFinal_PreservesEverythingElse(t *testing.T) {
	a := manifest.NewAggregator("ctr-x", "redis:7")
	a.RecordAdoptionMode(manifest.AdoptionNRIStart)
	a.RecordAttach(time.Now(), false)
	a.RecordFile("/usr/bin/redis-server", manifest.SourceDirect,
		[]manifest.AccessMode{manifest.AccessRead, manifest.AccessExecute}, time.Now())

	s, f := a.Snapshot(), a.SnapshotFinal()

	if f.ContainerID != s.ContainerID || f.ImageRef != s.ImageRef {
		t.Error("SnapshotFinal changed identity fields")
	}
	if f.SchemaVersion != s.SchemaVersion {
		t.Error("SnapshotFinal changed schema_version")
	}
	if len(f.Files) != len(s.Files) {
		t.Errorf("SnapshotFinal changed file count: %d vs %d", len(f.Files), len(s.Files))
	}
	if f.Coverage.AdoptionMode != s.Coverage.AdoptionMode {
		t.Error("SnapshotFinal changed adoption_mode")
	}
	if f.Coverage.ProcessStartObserved != s.Coverage.ProcessStartObserved {
		t.Error("SnapshotFinal changed process_start_observed")
	}
}
