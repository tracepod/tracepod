package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// writeManifest writes m as JSON to a temp file and returns its path.
func writeManifest(t *testing.T, m *manifest.Manifest) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "files.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// TestRunBuild_EmptyDirectManifest exercises the new --allow-empty gate.
// --source is a bogus, unreachable registry ref: a manifest with 0 direct
// entries must be rejected (exit 3) BEFORE any pull is attempted, so this
// test never touches the network. With --allow-empty the check is skipped
// and the build proceeds to the (now reachable) pull/build stage, which
// fails there instead — this test only asserts that failure is NOT exit 3,
// not that the build succeeds.
func TestRunBuild_EmptyDirectManifest(t *testing.T) {
	zeroDirect := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/lib/libc.so.6": {Source: manifest.SourceInferredELF},
			"/etc/passwd":    {Source: manifest.SourceManual},
		},
	}
	onlyDirect := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/bin/nginx": {Source: manifest.SourceDirect},
		},
	}

	const bogusSource = "harden-test-invalid.invalid/does-not-exist:latest"

	t.Run("zero direct entries without --allow-empty refuses before any network call", func(t *testing.T) {
		manifestPath := writeManifest(t, zeroDirect)
		outDir := t.TempDir()
		got := runBuild([]string{
			"--manifest", manifestPath,
			"--source", bogusSource,
			"--output", outDir,
		})
		if got != 3 {
			t.Errorf("runBuild() = %d, want 3 (empty-manifest refusal)", got)
		}
	})

	t.Run("manifest with only non-direct entries also refuses", func(t *testing.T) {
		// Same manifest as above by construction (no SourceDirect entries) —
		// listed separately to document the condition explicitly: it's the
		// count of SourceDirect entries specifically, not len(m.Files), that
		// gates the refusal.
		manifestPath := writeManifest(t, zeroDirect)
		outDir := t.TempDir()
		got := runBuild([]string{
			"--manifest", manifestPath,
			"--source", bogusSource,
			"--output", outDir,
		})
		if got != 3 {
			t.Errorf("runBuild() = %d, want 3 (empty-manifest refusal)", got)
		}
	})

	t.Run("zero direct entries with --allow-empty proceeds past the check", func(t *testing.T) {
		manifestPath := writeManifest(t, zeroDirect)
		outDir := t.TempDir()
		got := runBuild([]string{
			"--manifest", manifestPath,
			"--source", bogusSource,
			"--output", outDir,
			"--allow-empty",
		})
		if got == 3 {
			t.Errorf("runBuild() = 3 with --allow-empty, want the empty-manifest check to be skipped (bogus source should fail later, e.g. exit 1)")
		}
	})

	t.Run("manifest with direct entries is unaffected by the check", func(t *testing.T) {
		manifestPath := writeManifest(t, onlyDirect)
		outDir := t.TempDir()
		got := runBuild([]string{
			"--manifest", manifestPath,
			"--source", bogusSource,
			"--output", outDir,
		})
		if got == 3 {
			t.Errorf("runBuild() = 3 for a manifest with direct entries, want the empty-manifest check not to trigger")
		}
	})
}
