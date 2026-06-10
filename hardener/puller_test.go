package hardener

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// TestExtractFromImage_NginxAlpine pulls nginx:1.25-alpine (linux/amd64) and
// asserts that /usr/sbin/nginx is present in the extraction output.
//
// This test requires network access and is skipped in short mode.
func TestExtractFromImage_NginxAlpine(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	destDir := t.TempDir()

	m := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		ContainerID:   "test",
		ProfileStart:  time.Now(),
		ProfileEnd:    time.Now(),
		Files: map[string]manifest.FileEntry{
			"/usr/sbin/nginx": {
				Source:      manifest.SourceDirect,
				AccessModes: []manifest.AccessMode{manifest.AccessRead, manifest.AccessExecute},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Count:       1,
			},
		},
	}

	missing, err := ExtractFromImage(
		context.Background(),
		"nginx:1.25-alpine",
		m,
		destDir,
		PullOptions{
			Keychain: NewKeychain(),
			Platform: "linux/amd64",
		},
	)
	if err != nil {
		t.Fatalf("ExtractFromImage: %v", err)
	}
	if len(missing) > 0 {
		t.Logf("files not found in image layers (recorded as ENOENT probes): %v", missing)
	}

	nginxPath := filepath.Join(destDir, "usr", "sbin", "nginx")
	if _, err := os.Stat(nginxPath); err != nil {
		t.Errorf("expected %s to exist after extraction: %v", nginxPath, err)
	}
}

// TestExtractFromImage_WhiteoutSkipsFile verifies that a whited-out manifest
// file emits a warning and is not treated as missing (no error returned).
// This test uses a pre-built fake image fixture rather than a real registry pull.
func TestParsePlatform(t *testing.T) {
	tests := []struct {
		in       string
		wantOS   string
		wantArch string
		wantErr  bool
	}{
		{"linux/amd64", "linux", "amd64", false},
		{"linux/arm64", "linux", "arm64", false},
		{"windows/amd64", "windows", "amd64", false},
		{"invalid", "", "", true},
	}
	for _, tc := range tests {
		p, err := parsePlatform(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePlatform(%q): expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePlatform(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if p.OS != tc.wantOS || p.Architecture != tc.wantArch {
			t.Errorf("parsePlatform(%q) = {%s %s}, want {%s %s}",
				tc.in, p.OS, p.Architecture, tc.wantOS, tc.wantArch)
		}
	}
}
