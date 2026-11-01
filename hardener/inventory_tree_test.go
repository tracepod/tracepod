package hardener

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/tracepod/tracepod/manifest"
)

// tarStream writes hdrs (with empty bodies, except regular files which get
// one byte) into an in-memory tar stream.
func tarStream(t *testing.T, hdrs ...*tar.Header) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hdrs {
		if h.Typeflag == tar.TypeReg {
			h.Size = 1
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func dirH(n string) *tar.Header  { return &tar.Header{Typeflag: tar.TypeDir, Name: n} }
func fileH(n string) *tar.Header { return &tar.Header{Typeflag: tar.TypeReg, Name: n} }
func linkH(n, target string) *tar.Header {
	return &tar.Header{Typeflag: tar.TypeSymlink, Name: n, Linkname: target}
}

func TestReadLayerTree(t *testing.T) {
	for _, tc := range []struct {
		name string
		hdrs []*tar.Header
		want layerTree
	}{
		{
			name: "types, implicit parents, ./ prefix and root",
			hdrs: []*tar.Header{
				dirH("./"),
				fileH("./usr/bin/app"),
				linkH("usr/bin/app-link", "app"),
				{Typeflag: tar.TypeLink, Name: "usr/bin/hard", Linkname: "usr/bin/app"},
				{Typeflag: tar.TypeFifo, Name: "run/fifo"},
			},
			want: layerTree{
				"/usr":              {Type: "dir"},
				"/usr/bin":          {Type: "dir"},
				"/usr/bin/app":      {Type: "file"},
				"/usr/bin/app-link": {Type: "symlink", LinkTarget: "app"},
				"/usr/bin/hard":     {Type: "file"},
				"/run":              {Type: "dir"},
				"/run/fifo":         {Type: "other"},
			},
		},
		{
			// The hardened layer writes a symlink kept under its own name and
			// then the real parent directory of a path accessed through it.
			name: "directory replaces earlier symlink",
			hdrs: []*tar.Header{
				linkH("lib", "usr/lib"),
				dirH("lib/"),
				fileH("lib/libc.so.6"),
			},
			want: layerTree{
				"/lib":           {Type: "dir"},
				"/lib/libc.so.6": {Type: "file"},
			},
		},
		{
			name: "later non-directory replaces directory and its contents",
			hdrs: []*tar.Header{
				dirH("opt/"),
				fileH("opt/a"),
				dirH("opt/sub/"),
				fileH("opt/sub/b"),
				fileH("optional"),
				linkH("opt", "/srv"),
			},
			want: layerTree{
				"/opt":      {Type: "symlink", LinkTarget: "/srv"},
				"/optional": {Type: "file"},
			},
		},
		{
			name: "directory over directory keeps contents; last non-dir wins",
			hdrs: []*tar.Header{
				dirH("etc/"),
				fileH("etc/a"),
				dirH("etc/"),
				fileH("etc/b"),
				linkH("etc/b", "a"),
			},
			want: layerTree{
				"/etc":   {Type: "dir"},
				"/etc/a": {Type: "file"},
				"/etc/b": {Type: "symlink", LinkTarget: "a"},
			},
		},
		{
			name: "child under a non-directory parent replaces the parent",
			hdrs: []*tar.Header{
				fileH("x"),
				fileH("x/y"),
			},
			want: layerTree{
				"/x":   {Type: "dir"},
				"/x/y": {Type: "file"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readLayerTree(tarStream(t, tc.hdrs...))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestReadLayerTree_Corrupt(t *testing.T) {
	if _, err := readLayerTree(strings.NewReader(strings.Repeat("z", 1024))); err == nil {
		t.Fatal("want error for a corrupt stream")
	}
}

// writeUsrmergeTree creates a merged-/usr source tree: /bin, /lib and /sbin
// are symlinks into /usr.
func writeUsrmergeTree(t *testing.T, root string) {
	t.Helper()
	writeTreeFile(t, root, "usr/bin/date", "date")
	writeTreeFile(t, root, "usr/bin/python3.12", "py")
	writeTreeFile(t, root, "usr/sbin/nologin", "n")
	writeTreeFile(t, root, "usr/lib/aarch64-linux-gnu/libc.so.6", "libc")
	writeTreeFile(t, root, "usr/lib/aarch64-linux-gnu/libm.so.6", "libm")
	writeTreeFile(t, root, "usr/lib/ld-linux-aarch64.so.1", "ld")
	for name, target := range map[string]string{
		"bin":                "usr/bin",
		"lib":                "usr/lib",
		"sbin":               "usr/sbin",
		"usr/bin/python3":    "python3.12",
		"usr/bin/python-abs": "/usr/bin/python3.12",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

type invWant struct {
	inSource, inHardened bool
	typ, link            string
	hType, hLink         string
}

func checkInventory(t *testing.T, got []InventoryEntry, want map[string]invWant) {
	t.Helper()
	inv := byPath(got)
	for p, w := range want {
		e, ok := inv[p]
		if !w.inSource && !w.inHardened {
			if ok {
				t.Errorf("%s must not be listed: %+v", p, e)
			}
			continue
		}
		if !ok {
			t.Errorf("%s missing", p)
			continue
		}
		g := invWant{e.InSource, e.InHardened, e.Type, e.LinkTarget, e.HardenedType, e.HardenedLinkTarget}
		if g != w {
			t.Errorf("%s:\n got  %+v\n want %+v", p, g, w)
		}
	}
}

func TestCollectInventory_UsrmergeAccessedThroughParentSymlink(t *testing.T) {
	root := t.TempDir()
	writeUsrmergeTree(t, root)
	// The workload opened the library and the interpreter through the /lib
	// and /bin symlinks; /usr/bin/date was never used.
	got, err := collectInventory(root, layerFor(t, root,
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/lib/ld-linux-aarch64.so.1",
		"/bin/python3",
	))
	if err != nil {
		t.Fatal(err)
	}
	checkInventory(t, got, map[string]invWant{
		// Source symlinks the layer holds as real directories.
		"/lib": {inSource: true, inHardened: true, typ: "symlink", link: "usr/lib", hType: "dir"},
		"/bin": {inSource: true, inHardened: true, typ: "symlink", link: "usr/bin", hType: "dir"},
		// Paths that exist only in the hardened layer.
		"/lib/aarch64-linux-gnu":           {inHardened: true, hType: "dir"},
		"/lib/aarch64-linux-gnu/libc.so.6": {inHardened: true, hType: "file"},
		"/lib/ld-linux-aarch64.so.1":       {inHardened: true, hType: "file"},
		"/bin/python3":                     {inHardened: true, hType: "symlink", hLink: "python3.12"},
		// The symlink's relative target is kept beside it, under /bin.
		"/bin/python3.12": {inHardened: true, hType: "file"},
		// Source-only.
		"/sbin":                                 {inSource: true, typ: "symlink", link: "usr/sbin"},
		"/usr/bin/date":                         {inSource: true, typ: "file"},
		"/usr/bin/python3":                      {inSource: true, typ: "symlink", link: "python3.12"},
		"/usr/lib/aarch64-linux-gnu/libc.so.6":  {inSource: true, typ: "file"},
		"/usr/lib/aarch64-linux-gnu/libm.so.6":  {inSource: true, typ: "file"},
		"/usr":                                  {inSource: true, typ: "dir"},
		"/lib/aarch64-linux-gnu/libm.so.6":      {},
		"/bin/date":                             {},
		"/usr/lib/aarch64-linux-gnu/libc.so.6x": {},
	})
}

func TestCollectInventory_UsrmergeSymlinkKeptAndOverridden(t *testing.T) {
	root := t.TempDir()
	writeUsrmergeTree(t, root)

	// Only the canonical paths plus the /bin symlink itself are kept: /bin
	// stays a symlink in the hardened layer.
	got, err := collectInventory(root, layerFor(t, root, "/bin", "/usr/bin/python3.12"))
	if err != nil {
		t.Fatal(err)
	}
	checkInventory(t, got, map[string]invWant{
		"/bin":                {inSource: true, inHardened: true, typ: "symlink", link: "usr/bin", hType: "symlink", hLink: "usr/bin"},
		"/usr":                {inSource: true, inHardened: true, typ: "dir", hType: "dir"},
		"/usr/bin":            {inSource: true, inHardened: true, typ: "dir", hType: "dir"},
		"/usr/bin/python3.12": {inSource: true, inHardened: true, typ: "file", hType: "file"},
		"/usr/bin/date":       {inSource: true, typ: "file"},
		"/lib":                {inSource: true, typ: "symlink", link: "usr/lib"},
	})

	// The symlink is kept AND a path below it is accessed by its symlinked
	// name: the layer writes the symlink first, then a real /lib directory,
	// so the directory is what the hardened image holds.
	got, err = collectInventory(root, layerFor(t, root, "/lib", "/lib/aarch64-linux-gnu/libc.so.6"))
	if err != nil {
		t.Fatal(err)
	}
	checkInventory(t, got, map[string]invWant{
		"/lib":                             {inSource: true, inHardened: true, typ: "symlink", link: "usr/lib", hType: "dir"},
		"/lib/aarch64-linux-gnu/libc.so.6": {inHardened: true, hType: "file"},
		// The symlink's target was added to the layer too.
		"/usr/lib":                             {inSource: true, inHardened: true, typ: "dir", hType: "dir"},
		"/usr/lib/aarch64-linux-gnu/libc.so.6": {inSource: true, typ: "file"},
	})
}

func TestDecodeInventory_Versions(t *testing.T) {
	v1doc := `{"version":1,"source_digest":"sha256:aa","hardened_digest":"sha256:bb","files":[
		{"path":"/bin","type":"dir","in_hardened":true},
		{"path":"/lib","type":"symlink","link_target":"usr/lib","in_hardened":false}]}`
	f, err := DecodeInventory(strings.NewReader(v1doc))
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || f.DescribesHardenedTree() || len(f.Files) != 2 {
		t.Fatalf("v1: %+v", f)
	}
	want := []InventoryEntry{
		{Path: "/bin", Type: "dir", InHardened: true, InSource: true},
		{Path: "/lib", Type: "symlink", LinkTarget: "usr/lib", InSource: true},
	}
	if !reflect.DeepEqual(f.Files, want) {
		t.Errorf("v1 files:\n got  %+v\n want %+v", f.Files, want)
	}

	v2doc := `{"version":2,"files":[
		{"path":"/lib","type":"symlink","link_target":"usr/lib","in_hardened":true,"in_source":true,"hardened_type":"dir"},
		{"path":"/lib/libc.so.6","in_hardened":true,"in_source":false,"hardened_type":"file"}]}`
	f, err = DecodeInventory(strings.NewReader(v2doc))
	if err != nil {
		t.Fatal(err)
	}
	if !f.DescribesHardenedTree() || f.Files[1].InSource || f.Files[1].HardenedType != "file" || f.Files[0].HardenedType != "dir" {
		t.Fatalf("v2: %+v", f)
	}

	f, err = DecodeInventory(strings.NewReader(`{"version":2}`))
	if err != nil || f.Files == nil {
		t.Fatalf("missing files must decode as empty: %+v %v", f, err)
	}

	for _, bad := range []string{`{"version":0,"files":[]}`, `{"files":[]}`, `{"version":3,"files":[]}`, `not json`} {
		if _, err := DecodeInventory(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	if _, err := ReadInventory(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("ReadInventory: want error for a missing file")
	}
}

// pushUsrmergeFixture pushes a merged-/usr image to an in-process registry.
func pushUsrmergeFixture(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tarStream(t,
		dirH("usr/"), dirH("usr/bin/"), dirH("usr/lib/"), dirH("usr/lib/aarch64-linux-gnu/"),
		fileH("usr/bin/date"), fileH("usr/bin/app"),
		fileH("usr/lib/aarch64-linux-gnu/libc.so.6"), fileH("usr/lib/aarch64-linux-gnu/libm.so.6"),
		linkH("bin", "usr/bin"), linkH("lib", "usr/lib"),
	)); err != nil {
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
	ref := strings.TrimPrefix(srv.URL, "http://") + "/inv/usrmerge:latest"
	if err := crane.Push(img, ref, crane.Insecure); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestBuildImage_InventoryUsrmerge(t *testing.T) {
	ref := pushUsrmergeFixture(t)
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/bin/app":                         {Source: manifest.SourceDirect},
		"/lib/aarch64-linux-gnu/libc.so.6": {Source: manifest.SourceDirect},
	}}
	outDir := t.TempDir()
	res, err := BuildImage(t.Context(), ref, m, outDir, BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true, RecordInventory: true,
	})
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if res.InventoryErr != nil {
		t.Fatalf("inventory: %v", res.InventoryErr)
	}
	checkInventory(t, res.Inventory, map[string]invWant{
		"/bin":                                 {inSource: true, inHardened: true, typ: "symlink", link: "usr/bin", hType: "dir"},
		"/lib":                                 {inSource: true, inHardened: true, typ: "symlink", link: "usr/lib", hType: "dir"},
		"/bin/app":                             {inHardened: true, hType: "file"},
		"/lib/aarch64-linux-gnu":               {inHardened: true, hType: "dir"},
		"/lib/aarch64-linux-gnu/libc.so.6":     {inHardened: true, hType: "file"},
		"/usr/bin/date":                        {inSource: true, typ: "file"},
		"/usr/bin/app":                         {inSource: true, typ: "file"},
		"/usr/lib/aarch64-linux-gnu/libc.so.6": {inSource: true, typ: "file"},
		"/usr":                                 {inSource: true, typ: "dir"},
		"/bin/date":                            {},
	})

	// The hardened part of the inventory is exactly the layer's non-directory
	// contents.
	layerFiles := layerNonDirPaths(t, outDir)
	for _, e := range res.Inventory {
		if e.InHardened && e.HardenedType != "dir" && !layerFiles[e.Path] {
			t.Errorf("%s listed as hardened %s but not in the layer", e.Path, e.HardenedType)
		}
		delete(layerFiles, e.Path)
	}
	if len(layerFiles) != 0 {
		t.Errorf("layer paths missing from the inventory: %v", layerFiles)
	}
}
