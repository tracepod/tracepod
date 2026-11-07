package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tracepod/tracepod/hardener"
	"github.com/tracepod/tracepod/manifest"
)

// TestWriteMissingIncludeWarnings checks the exact Warning lines printed for
// an --include path that is absent (ENOENT) and one that lies beneath a
// regular file (ENOTDIR). The reasons come from the real staging directory.
func TestWriteMissingIncludeWarnings(t *testing.T) {
	staging := t.TempDir()
	if err := os.WriteFile(filepath.Join(staging, "foo.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{}}
	includes := []string{"/var/log/nginx", "/foo.php/sub"}
	_, missing, err := hardener.ApplyDirectoryInclusion(staging, includes, m)
	if err != nil {
		t.Fatalf("ApplyDirectoryInclusion: %v", err)
	}

	result := hardener.BuildResult{
		MissingIncludes:       missing,
		MissingIncludeReasons: map[string]string{},
	}
	for _, p := range missing {
		result.MissingIncludeReasons[p] = hardener.MissingIncludeReason(staging, p)
	}

	var buf bytes.Buffer
	writeMissingIncludeWarnings(&buf, result)

	want := "" +
		"Warning:     --include /var/log/nginx: not found in source image (directory may be created at runtime)\n" +
		"Warning:     --include /foo.php/sub: lies beneath a file (/foo.php is not a directory); it cannot exist\n"
	if got := buf.String(); got != want {
		t.Errorf("warning output mismatch\n got: %q\nwant: %q", got, want)
	}
}
