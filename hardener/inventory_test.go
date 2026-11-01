package hardener

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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

func set(paths ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		s[p] = struct{}{}
	}
	return s
}

func byPath(entries []InventoryEntry) map[string]InventoryEntry {
	m := make(map[string]InventoryEntry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

func writeTreeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectInventory_TypesAndOrdering(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, "bin/app", "x")
	writeTreeFile(t, root, "etc/zz.conf", "x")
	writeTreeFile(t, root, "etc/aa.conf", "x")
	if err := os.Symlink("app", filepath.Join(root, "bin/app-link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc/pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	got, err := collectInventory(root, set("/bin/app"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range got {
		paths = append(paths, e.Path)
	}
	want := []string{"/bin", "/bin/app", "/bin/app-link", "/etc", "/etc/aa.conf", "/etc/pipe", "/etc/zz.conf"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	m := byPath(got)
	for path, typ := range map[string]string{
		"/bin": "dir", "/bin/app": "file", "/bin/app-link": "symlink", "/etc/pipe": "other", "/etc/aa.conf": "file",
	} {
		if m[path].Type != typ {
			t.Errorf("%s type = %q, want %q", path, m[path].Type, typ)
		}
	}
	for path, kept := range map[string]bool{
		"/bin": true, "/bin/app": true, "/bin/app-link": false, "/etc": false, "/etc/aa.conf": false, "/etc/pipe": false,
	} {
		if m[path].InHardened != kept {
			t.Errorf("%s in_hardened = %v, want %v", path, m[path].InHardened, kept)
		}
	}
	for _, e := range got {
		if strings.HasSuffix(e.Path, "/") || !strings.HasPrefix(e.Path, "/") {
			t.Errorf("malformed path %q", e.Path)
		}
	}
}

func TestCollectInventory_AncestorDirsInHardened(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, "usr/lib/x86/deep/lib.so", "x")
	writeTreeFile(t, root, "usr/lib/other/f", "x")
	writeTreeFile(t, root, "usr/share/doc/readme", "x")

	got, err := collectInventory(root, set("/usr/lib/x86/deep/lib.so"))
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(got)
	for _, d := range []string{"/usr", "/usr/lib", "/usr/lib/x86", "/usr/lib/x86/deep"} {
		if !m[d].InHardened {
			t.Errorf("ancestor %s should be in_hardened", d)
		}
	}
	for _, p := range []string{"/usr/lib/other", "/usr/lib/other/f", "/usr/share", "/usr/share/doc", "/usr/share/doc/readme"} {
		if m[p].InHardened {
			t.Errorf("%s should not be in_hardened", p)
		}
	}
}

func TestCollectInventory_EnsureEntriesNotListed(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, "bin/app", "x")
	got, err := collectInventory(root, set("/bin/app", "/run/app.pid", "/var/cache/tmp", "/etc/fabricated"))
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(got)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (/bin, /bin/app): %+v", len(got), got)
	}
	for _, p := range []string{"/run", "/run/app.pid", "/var", "/var/cache/tmp", "/etc/fabricated"} {
		if _, ok := m[p]; ok {
			t.Errorf("%s must not be listed (absent from source tree)", p)
		}
	}
}

func TestCollectInventory_SymlinkTarget(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, "usr/lib/libz.so.1.3", "x")
	links := map[string]string{
		"usr/lib/libz.so.1": "libz.so.1.3",          // relative
		"usr/lib/abs":       "/usr/lib/libz.so.1.3", // absolute
		"usr/lib/dangling":  "does/not/exist",       // dangling
		"usr/lib/up":        "../../etc/passwd",     // escapes root, never resolved
		"usr/lib/dirlink":   "/usr",                 // points at a dir; must not be followed
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := collectInventory(root, set())
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(got)
	for name, target := range links {
		e := m["/"+name]
		if e.Type != "symlink" || e.LinkTarget != target {
			t.Errorf("/%s = %+v, want symlink -> %q", name, e, target)
		}
	}
	if e := m["/usr/lib/libz.so.1.3"]; e.Type != "file" || e.LinkTarget != "" {
		t.Errorf("regular file entry wrong: %+v", e)
	}
	// dirlink must not have caused descent into /usr again.
	n := 0
	for _, e := range got {
		if strings.HasPrefix(e.Path, "/usr/lib/dirlink/") {
			n++
		}
	}
	if n != 0 {
		t.Errorf("symlinked directory was followed (%d children)", n)
	}
}

func TestCollectInventory_HardlinksAreFiles(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, "bin/busybox", "x")
	if err := os.Link(filepath.Join(root, "bin/busybox"), filepath.Join(root, "bin/sh")); err != nil {
		t.Fatal(err)
	}
	got, err := collectInventory(root, set("/bin/busybox"))
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(got)
	if m["/bin/sh"].Type != "file" || m["/bin/sh"].InHardened {
		t.Errorf("/bin/sh = %+v", m["/bin/sh"])
	}
	if m["/bin/busybox"].Type != "file" || !m["/bin/busybox"].InHardened {
		t.Errorf("/bin/busybox = %+v", m["/bin/busybox"])
	}
}

func TestCollectInventory_EmptyTreeAndMissingRoot(t *testing.T) {
	got, err := collectInventory(t.TempDir(), set())
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty tree: got %v, %v", got, err)
	}
	if _, err := collectInventory(filepath.Join(t.TempDir(), "nope"), set()); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestInventoryFile_JSONContract(t *testing.T) {
	in := InventoryFile{
		Version: InventoryVersion, SourceDigest: "sha256:aa", HardenedDigest: "sha256:bb",
		Files: []InventoryEntry{
			{Path: "/bin", Type: "dir", InHardened: true},
			{Path: "/bin/sh", Type: "symlink", LinkTarget: "busybox", InHardened: false},
		},
	}
	path := filepath.Join(t.TempDir(), "sub", "dir", "inv.json")
	if err := WriteInventory(path, in); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.HasPrefix(raw, []byte("{\n  \"version\": 1,")) || !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Errorf("unexpected formatting:\n%s", raw)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "source_digest", "hardened_digest", "files"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	files := generic["files"].([]any)
	if _, has := files[0].(map[string]any)["link_target"]; has {
		t.Error("link_target must be omitted when empty")
	}
	if files[1].(map[string]any)["link_target"] != "busybox" {
		t.Error("link_target missing for symlink")
	}
	if files[0].(map[string]any)["in_hardened"] != true || files[1].(map[string]any)["in_hardened"] != false {
		t.Error("in_hardened must always be present")
	}
	var out InventoryFile
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}

	// nil Files serialises as [] not null.
	p2 := filepath.Join(t.TempDir(), "e.json")
	if err := WriteInventory(p2, InventoryFile{Version: 1}); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(p2)
	if !strings.Contains(string(raw2), `"files": []`) {
		t.Errorf("nil Files should render as []:\n%s", raw2)
	}
}

func TestParentPath(t *testing.T) {
	for in, want := range map[string]string{"/a/b/c": "/a/b", "/a": "/", "/": "/", "": "/"} {
		if got := parentPath(in); got != want {
			t.Errorf("parentPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// pushInventoryFixture pushes a small synthetic two-layer image (with a
// whiteout, symlinks and a hardlink) to an in-process registry and returns its
// reference. Fully offline.
func pushInventoryFixture(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	layer := func(build func(tw *tar.Writer)) v1.Layer {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		build(tw)
		tw.Close()
		data := buf.Bytes()
		l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	dir := func(tw *tar.Writer, n string) {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: n + "/", Mode: 0o755})
	}
	file := func(tw *tar.Writer, n, c string) {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(c))})
		tw.Write([]byte(c))
	}
	l1 := layer(func(tw *tar.Writer) {
		dir(tw, "bin")
		dir(tw, "etc")
		dir(tw, "usr")
		dir(tw, "usr/share")
		file(tw, "bin/app", "app-binary")
		file(tw, "bin/busybox", "busybox")
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "bin/sh", Linkname: "bin/busybox"})
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "bin/app-link", Linkname: "app"})
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "bin/broken", Linkname: "/nowhere"})
		file(tw, "etc/passwd", "root:x:0:0::/:/bin/sh\n")
		file(tw, "etc/removed-later", "x")
		file(tw, "usr/share/doc.txt", "docs")
	})
	l2 := layer(func(tw *tar.Writer) {
		file(tw, "etc/.wh.removed-later", "")
	})
	img, err := mutate.AppendLayers(empty.Image, l1, l2)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architecture, cfg.OS = "amd64", "linux"
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/inv/fixture:latest"
	if err := crane.Push(img, ref, crane.Insecure); err != nil {
		t.Fatal(err)
	}
	return ref
}

func inventoryFixtureManifest() *manifest.Manifest {
	return &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/bin/app":    {Source: manifest.SourceDirect},
		"/etc/passwd": {Source: manifest.SourceDirect},
	}}
}

func TestBuildImage_InventoryOptIn(t *testing.T) {
	ref := pushInventoryFixture(t)

	// Default: no inventory, result otherwise unchanged.
	off, err := BuildImage(t.Context(), ref, inventoryFixtureManifest(), t.TempDir(), BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true,
	})
	if err != nil {
		t.Fatalf("BuildImage (off): %v", err)
	}
	if off.Inventory != nil || off.InventoryErr != nil {
		t.Fatalf("inventory must be nil/no-error by default: %+v %v", off.Inventory, off.InventoryErr)
	}

	m := inventoryFixtureManifest()
	outDir := t.TempDir()
	on, err := BuildImage(t.Context(), ref, m, outDir, BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true, RecordInventory: true,
	})
	if err != nil {
		t.Fatalf("BuildImage (on): %v", err)
	}
	if on.InventoryErr != nil || on.Inventory == nil {
		t.Fatalf("inventory missing: err=%v", on.InventoryErr)
	}

	// Existing fields identical with and without the inventory.
	if on.LayerDigest != off.LayerDigest || on.FileCount != off.FileCount ||
		on.SourceDigest != off.SourceDigest || on.EnsuredCount != off.EnsuredCount {
		t.Errorf("recording inventory changed existing result fields:\n on=%+v\noff=%+v", on, off)
	}

	inv := byPath(on.Inventory)
	// Whiteout-deleted file absent.
	if _, ok := inv["/etc/removed-later"]; ok {
		t.Error("whiteout-deleted file must be absent")
	}
	if _, ok := inv["/etc/.wh.removed-later"]; ok {
		t.Error("whiteout marker must not be listed")
	}
	// Every manifest path (== final retained set) that exists in source is in_hardened.
	for p := range m.Files {
		if e, ok := inv[p]; ok && !e.InHardened {
			t.Errorf("retained %s has in_hardened=false", p)
		}
	}
	// Known-removed files.
	for _, p := range []string{"/bin/busybox", "/bin/sh", "/usr/share/doc.txt"} {
		if inv[p].InHardened {
			t.Errorf("%s should not be in hardened image", p)
		}
	}
	// Hardlink is a plain file.
	if inv["/bin/sh"].Type != "file" {
		t.Errorf("hardlink type = %q, want file", inv["/bin/sh"].Type)
	}
	// Parent dirs of retained files kept; unrelated dir not.
	if !inv["/bin"].InHardened || !inv["/etc"].InHardened {
		t.Error("parents of retained files must be in_hardened")
	}
	if inv["/usr"].InHardened || inv["/usr/share"].InHardened {
		t.Error("dirs with no retained descendants must not be in_hardened")
	}
	// Symlinks verbatim.
	if e := inv["/bin/app-link"]; e.Type != "symlink" || e.LinkTarget != "app" {
		t.Errorf("app-link = %+v", e)
	}
	if e := inv["/bin/broken"]; e.Type != "symlink" || e.LinkTarget != "/nowhere" {
		t.Errorf("broken = %+v", e)
	}

	// in_hardened non-dir entries match the layer contents.
	layerFiles := layerNonDirPaths(t, outDir)
	kept := 0
	for _, e := range on.Inventory {
		if e.InHardened && e.Type != "dir" {
			kept++
			if !layerFiles[e.Path] {
				t.Errorf("%s in_hardened but not in layer", e.Path)
			}
		}
	}
	if kept != len(layerFiles) {
		t.Errorf("in_hardened non-dir count %d != layer entries %d", kept, len(layerFiles))
	}
}

// layerNonDirPaths returns the "/"-rooted non-directory entries of the single
// layer of the image in the OCI layout at outDir.
func layerNonDirPaths(t *testing.T, outDir string) map[string]bool {
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
	layers, err := img.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers: %v (%d)", err, len(layers))
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	out := map[string]bool{}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeDir {
			out["/"+strings.TrimSuffix(h.Name, "/")] = true
		}
	}
	return out
}
