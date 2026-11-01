package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/tracepod/tracepod/hardener"
	"github.com/tracepod/tracepod/manifest"
)

// pushTinyImage pushes a one-layer image to an in-process registry and returns
// its reference. Fully offline.
func pushTinyImage(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "bin/", Mode: 0o755})
	for name, body := range map[string]string{"bin/app": "app", "bin/unused": "unused", "etc-passwd": "x"} {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "bin/link", Linkname: "app"})
	tw.Close()
	data := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, l)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := img.ConfigFile()
	cfg.Architecture, cfg.OS = "amd64", "linux"
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/cli/tiny:latest"
	if err := crane.Push(img, ref, crane.Insecure); err != nil {
		t.Fatal(err)
	}
	return ref
}

func tinyManifest() *manifest.Manifest {
	return &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/bin/app": {Source: manifest.SourceDirect},
	}}
}

// runTinyBuild runs `harden build` and fails unless it exits 0 or 2; exit 2
// (scratch-compat warnings for the synthetic image) still means it was built.
func runTinyBuild(t *testing.T, ref, outDir string, extra ...string) {
	t.Helper()
	args := append([]string{
		"--manifest", writeManifest(t, tinyManifest()),
		"--source", ref,
		"--output", outDir,
		"--insecure",
		"--platform", "linux/amd64",
	}, extra...)
	if code := runBuild(args); code != 0 && code != 2 {
		t.Fatalf("runBuild exit %d", code)
	}
}

func readInventory(t *testing.T, path string) hardener.InventoryFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var f hardener.InventoryFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse inventory: %v", err)
	}
	return f
}

func layoutDigest(t *testing.T, outDir string) v1.Hash {
	t.Helper()
	idx, err := layout.ImageIndexFromPath(outDir)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil || len(im.Manifests) != 1 {
		t.Fatalf("index: %v", err)
	}
	return im.Manifests[0].Digest
}

func TestHardenBuild_InventoryDefaultAndOverride(t *testing.T) {
	ref := pushTinyImage(t)

	t.Run("default path", func(t *testing.T) {
		out := t.TempDir()
		runTinyBuild(t, ref, out)
		f := readInventory(t, filepath.Join(out, "inventory.json"))
		if f.Version != 1 {
			t.Errorf("version = %d", f.Version)
		}
		if f.HardenedDigest != layoutDigest(t, out).String() {
			t.Errorf("hardened_digest %s != build digest %s", f.HardenedDigest, layoutDigest(t, out))
		}
		if !strings.HasPrefix(f.SourceDigest, "sha256:") {
			t.Errorf("source_digest = %q", f.SourceDigest)
		}
		got := map[string]hardener.InventoryEntry{}
		for _, e := range f.Files {
			got[e.Path] = e
		}
		if !got["/bin/app"].InHardened || !got["/bin"].InHardened {
			t.Error("retained file and parent dir must be in_hardened")
		}
		if got["/bin/unused"].InHardened || got["/etc-passwd"].InHardened {
			t.Error("unobserved files must not be in_hardened")
		}
		if e := got["/bin/link"]; e.Type != "symlink" || e.LinkTarget != "app" {
			t.Errorf("link entry = %+v", e)
		}
	})

	t.Run("override path", func(t *testing.T) {
		out := t.TempDir()
		custom := filepath.Join(t.TempDir(), "nested", "inv.json")
		runTinyBuild(t, ref, out, "--inventory-out", custom)
		if f := readInventory(t, custom); len(f.Files) == 0 {
			t.Error("override inventory empty")
		}
		if _, err := os.Stat(filepath.Join(out, "inventory.json")); !os.IsNotExist(err) {
			t.Errorf("default inventory.json must not be written when --inventory-out is set (err=%v)", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		out := t.TempDir()
		custom := filepath.Join(t.TempDir(), "inv.json")
		runTinyBuild(t, ref, out, "--no-inventory", "--inventory-out", custom)
		for _, p := range []string{filepath.Join(out, "inventory.json"), custom} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("%s must not exist with --no-inventory (err=%v)", p, err)
			}
		}
	})

	t.Run("write failure is a non-zero exit", func(t *testing.T) {
		out := t.TempDir()
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		args := []string{
			"--manifest", writeManifest(t, tinyManifest()),
			"--source", ref, "--output", out, "--insecure", "--platform", "linux/amd64",
			"--inventory-out", filepath.Join(blocker, "inv.json"), // parent is a file
		}
		if code := runBuild(args); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
}
