package hardener

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

	"github.com/tracepod/tracepod/manifest"
)

// layerHeader is one tar entry of a hardened layer, in stream order.
type layerHeader struct {
	Name     string
	Typeflag byte
	Linkname string
}

// readLayerHeaders returns every entry of an uncompressed layer tar stream.
func readLayerHeaders(t *testing.T, r io.Reader) []layerHeader {
	t.Helper()
	var out []layerHeader
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal("tar.Next:", err)
		}
		out = append(out, layerHeader{Name: h.Name, Typeflag: h.Typeflag, Linkname: h.Linkname})
	}
}

// buildLayerHeaders runs buildLayer and returns its entries.
func buildLayerHeaders(t *testing.T, m *manifest.Manifest, root string) []layerHeader {
	t.Helper()
	rc, err := buildLayer(m, root)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rc); err != nil {
		t.Fatalf("buildLayer: %v", err)
	}
	return readLayerHeaders(t, gunzip(t, &buf))
}

func gunzip(t *testing.T, r io.Reader) io.Reader {
	t.Helper()
	gr, err := gzip.NewReader(r)
	if err != nil {
		t.Fatal(err)
	}
	return gr
}

// assertOnlyEntry requires exactly one entry named name, of type want.
func assertOnlyEntry(t *testing.T, hs []layerHeader, name string, want byte) {
	t.Helper()
	var got []byte
	for _, h := range hs {
		if h.Name == name {
			got = append(got, h.Typeflag)
		}
	}
	if len(got) != 1 || got[0] != want {
		t.Errorf("entry %q: got typeflags %q, want exactly one %q (layer: %v)", name, got, want, names(hs))
	}
}

// assertNothingBelow requires that the layer holds no entry at or below the
// directory form of p ("p/" and "p/...").
func assertNothingBelow(t *testing.T, hs []layerHeader, p string) {
	t.Helper()
	for _, h := range hs {
		if strings.HasPrefix(h.Name, p+"/") {
			t.Errorf("layer must not hold %q under non-directory %q (layer: %v)", h.Name, p, names(hs))
		}
	}
}

func names(hs []layerHeader) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.Name
	}
	return out
}

func filesManifest(paths ...string) *manifest.Manifest {
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{}}
	for _, p := range paths {
		m.Files[p] = manifest.FileEntry{Source: manifest.SourceDirect}
	}
	return m
}

// An observed probe beneath a regular file (it fails with ENOTDIR at runtime)
// must not turn that file into a directory in the layer.
func TestBuildLayer_ProbeBelowFileKeepsFile(t *testing.T) {
	root := t.TempDir()
	createFile(t, root, "/x/foo.php")

	hs := buildLayerHeaders(t, filesManifest("/x/foo.php", "/x/foo.php/.htaccess"), root)
	assertOnlyEntry(t, hs, "x/", tar.TypeDir)
	assertOnlyEntry(t, hs, "x/foo.php", tar.TypeReg)
	assertNothingBelow(t, hs, "x/foo.php")
}

// Same, when only the probe was observed: the layer must not invent a
// directory where the source has a file.
func TestBuildLayer_ProbeBelowUnkeptFile(t *testing.T) {
	root := t.TempDir()
	createFile(t, root, "/x/foo.php")
	createFile(t, root, "/x/keep")

	hs := buildLayerHeaders(t, filesManifest("/x/keep", "/x/foo.php/.htaccess"), root)
	assertOnlyEntry(t, hs, "x/keep", tar.TypeReg)
	for _, h := range hs {
		if strings.HasPrefix(h.Name, "x/foo.php") {
			t.Errorf("unexpected entry %q (layer: %v)", h.Name, names(hs))
		}
	}
}

// A probe beneath a symlink to a regular file must not replace the symlink
// with a directory.
func TestBuildLayer_ProbeBelowSymlinkToFile(t *testing.T) {
	root := t.TempDir()
	createFile(t, root, "/x/foo.php")
	createSymlink(t, root, "/x/link", "foo.php")

	hs := buildLayerHeaders(t, filesManifest("/x/link", "/x/link/.htaccess"), root)
	assertOnlyEntry(t, hs, "x/link", tar.TypeSymlink)
	assertOnlyEntry(t, hs, "x/foo.php", tar.TypeReg) // symlink target
	assertNothingBelow(t, hs, "x/link")
	assertNothingBelow(t, hs, "x/foo.php")
}

// A probe beneath a dangling symlink must not replace the symlink either.
func TestBuildLayer_ProbeBelowDanglingSymlink(t *testing.T) {
	root := t.TempDir()
	createSymlink(t, root, "/x/dangling", "/nowhere")

	hs := buildLayerHeaders(t, filesManifest("/x/dangling", "/x/dangling/.htaccess"), root)
	assertOnlyEntry(t, hs, "x/dangling", tar.TypeSymlink)
	assertNothingBelow(t, hs, "x/dangling")
}

// Real directory parents are still created, including for a probe of a
// missing file inside an existing directory (the directory is kept).
func TestBuildLayer_RealDirParentsStillCreated(t *testing.T) {
	root := t.TempDir()
	createFile(t, root, "/x/sub/real.txt")
	mkdirIn(t, root, "/x/cache")

	hs := buildLayerHeaders(t, filesManifest("/x/sub/real.txt", "/x/cache/missing.txt"), root)
	assertOnlyEntry(t, hs, "x/", tar.TypeDir)
	assertOnlyEntry(t, hs, "x/sub/", tar.TypeDir)
	assertOnlyEntry(t, hs, "x/sub/real.txt", tar.TypeReg)
	assertOnlyEntry(t, hs, "x/cache/", tar.TypeDir)
}

// A file reached through a symlink to a directory (merged-/usr: /lib ->
// usr/lib) keeps today's layout: the accessed name's parent is written as a
// real directory.
func TestBuildLayer_SymlinkToDirParentUnchanged(t *testing.T) {
	root := t.TempDir()
	createFile(t, root, "/usr/lib/libc.so")
	createSymlink(t, root, "/lib", "usr/lib")

	hs := buildLayerHeaders(t, filesManifest("/lib/libc.so"), root)
	assertOnlyEntry(t, hs, "lib/", tar.TypeDir)
	assertOnlyEntry(t, hs, "lib/libc.so", tar.TypeReg)
}

// An ensure entry (--mkdir / --touch) beneath a regular file of the source
// must fail the layer instead of overwriting the file.
func TestBuildLayer_EnsureBelowFileFails(t *testing.T) {
	for _, src := range []manifest.ObservationSource{manifest.SourceEnsureDir, manifest.SourceEnsureFile} {
		t.Run(string(src), func(t *testing.T) {
			root := t.TempDir()
			createFile(t, root, "/x/foo.php")
			m := filesManifest("/x/foo.php")
			m.Files["/x/foo.php/sub"] = manifest.FileEntry{Source: src}

			rc, err := buildLayer(m, root)
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			if _, err := io.Copy(io.Discard, rc); err == nil || !strings.Contains(err.Error(), "/x/foo.php") {
				t.Fatalf("want an error naming /x/foo.php, got %v", err)
			}
		})
	}
}

// Two ensure entries that contradict each other (--touch /a, --mkdir /a/b)
// must fail rather than silently replace the file.
func TestBuildLayer_EnsureBelowEnsuredFileFails(t *testing.T) {
	root := t.TempDir()
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/new/a":   {Source: manifest.SourceEnsureFile},
		"/new/a/b": {Source: manifest.SourceEnsureDir},
	}}
	rc, err := buildLayer(m, root)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err == nil || !strings.Contains(err.Error(), "/new/a") {
		t.Fatalf("want an error naming /new/a, got %v", err)
	}
}

func mkdirIn(t *testing.T, root, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
		t.Fatal(err)
	}
}

// --- BuildImage end to end, through an in-process registry ---

// pushProbeFixture pushes a one-layer image holding
//
//	/x/foo.php            regular file
//	/x/link -> foo.php    symlink to a file
//	/x/sub/real.txt       regular file in a real directory
//	/usr/lib/libc.so      regular file
//	/lib -> usr/lib       symlink to a directory
//	/etc/passwd
func pushProbeFixture(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	dir := func(n string) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: n + "/", Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	file := func(n, c string) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(c))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	symlink := func(n, target string) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: n, Linkname: target}); err != nil {
			t.Fatal(err)
		}
	}
	dir("etc")
	file("etc/passwd", "root:x:0:0::/:/bin/sh\n")
	dir("x")
	file("x/foo.php", "<?php echo 1;")
	symlink("x/link", "foo.php")
	dir("x/sub")
	file("x/sub/real.txt", "real")
	dir("usr")
	dir("usr/lib")
	file("usr/lib/libc.so", "libc")
	symlink("lib", "usr/lib")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
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
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architecture, cfg.OS = "amd64", "linux"
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/probe/fixture:latest"
	if err := crane.Push(img, ref, crane.Insecure); err != nil {
		t.Fatal(err)
	}
	return ref
}

// hardenedLayerHeaders returns the entries of the single layer of the image in
// the OCI layout at outDir.
func hardenedLayerHeaders(t *testing.T, outDir string) []layerHeader {
	t.Helper()
	idx, err := layout.ImageIndexFromPath(outDir)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil || len(im.Manifests) != 1 {
		t.Fatalf("index manifest: %v (%d)", err, len(im.Manifests))
	}
	img, err := idx.Image(im.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	var layers []v1.Layer
	if layers, err = img.Layers(); err != nil || len(layers) != 1 {
		t.Fatalf("layers: %v (%d)", err, len(layers))
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	return readLayerHeaders(t, rc)
}

func TestBuildImage_ProbeBelowFileKeepsFile(t *testing.T) {
	ref := pushProbeFixture(t)
	m := filesManifest(
		"/x/foo.php",
		"/x/foo.php/.htaccess", // ENOTDIR probe below a file
		"/x/link",
		"/x/link/.htaccess", // ENOTDIR probe below a symlink to a file
		"/x/sub/real.txt",
		"/x/sub/missing.txt", // ENOENT probe in a real directory
		"/lib/libc.so",       // reached through a symlink to a directory
	)
	outDir := t.TempDir()
	if _, err := BuildImage(t.Context(), ref, m, outDir, BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true,
	}); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	hs := hardenedLayerHeaders(t, outDir)
	assertOnlyEntry(t, hs, "x/foo.php", tar.TypeReg)
	assertNothingBelow(t, hs, "x/foo.php")
	assertOnlyEntry(t, hs, "x/link", tar.TypeSymlink)
	assertNothingBelow(t, hs, "x/link")
	assertOnlyEntry(t, hs, "x/", tar.TypeDir)
	assertOnlyEntry(t, hs, "x/sub/", tar.TypeDir)
	assertOnlyEntry(t, hs, "x/sub/real.txt", tar.TypeReg)
	assertOnlyEntry(t, hs, "lib/", tar.TypeDir)
	assertOnlyEntry(t, hs, "lib/libc.so", tar.TypeReg)
}

func TestBuildImage_EnsurePathBelowFileFails(t *testing.T) {
	ref := pushProbeFixture(t)
	cases := []EnsureEntry{
		{Path: "/x/foo.php/sub", IsDir: true},
		{Path: "/x/foo.php/new.txt", IsDir: false},
		{Path: "/x/link/sub", IsDir: true},
	}
	for _, e := range cases {
		t.Run(e.Path, func(t *testing.T) {
			_, err := BuildImage(t.Context(), ref, filesManifest("/x/foo.php"), t.TempDir(), BuildOptions{
				Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true,
				EnsurePaths: []EnsureEntry{e},
			})
			if err == nil {
				t.Fatalf("BuildImage with ensure path %s below a file: want error, got nil", e.Path)
			}
			if !strings.Contains(err.Error(), e.Path) || !strings.Contains(err.Error(), "not a directory") {
				t.Errorf("error should name %s and say why: %v", e.Path, err)
			}
		})
	}
}

// Ensure paths under real or missing directories still work end to end.
func TestBuildImage_EnsurePathsNormal(t *testing.T) {
	ref := pushProbeFixture(t)
	outDir := t.TempDir()
	if _, err := BuildImage(t.Context(), ref, filesManifest("/x/foo.php"), outDir, BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true,
		EnsurePaths: []EnsureEntry{
			{Path: "/x/sub/new", IsDir: true},
			{Path: "/new/a/b", IsDir: true},
			{Path: "/new/f.txt", IsDir: false},
		},
	}); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	hs := hardenedLayerHeaders(t, outDir)
	assertOnlyEntry(t, hs, "x/sub/new/", tar.TypeDir)
	assertOnlyEntry(t, hs, "new/", tar.TypeDir)
	assertOnlyEntry(t, hs, "new/a/", tar.TypeDir)
	assertOnlyEntry(t, hs, "new/a/b/", tar.TypeDir)
	assertOnlyEntry(t, hs, "new/f.txt", tar.TypeReg)
	assertOnlyEntry(t, hs, "x/foo.php", tar.TypeReg)
}
