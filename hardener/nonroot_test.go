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
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/tracepod/tracepod/manifest"
)

// The tests in this file check that the hardened layer depends only on the
// source image, never on the user the hardener runs as. They run as the
// current user: as non-root they exercise the unprivileged path (0000 files,
// 0500 directories, no mknod, no security.* xattrs), and as root they must
// produce the same result. TestBuildImage_SpecialModes logs the hardened
// layer digest so the two can be compared across users.

// fixtureEntry is one tar entry of a synthetic source layer.
type fixtureEntry struct {
	hdr  tar.Header
	body []byte
}

var fixtureTime = time.Unix(1700000000, 0).UTC()

func fxDir(name string, mode int64, uid, gid int) fixtureEntry {
	return fixtureEntry{hdr: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode, Uid: uid, Gid: gid, ModTime: fixtureTime}}
}

func fxFile(name string, mode int64, uid, gid int, body string) fixtureEntry {
	return fixtureEntry{
		hdr:  tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Uid: uid, Gid: gid, ModTime: fixtureTime.Add(time.Duration(len(name)) * time.Hour)},
		body: []byte(body),
	}
}

func layerFromEntries(t *testing.T, entries []fixtureEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		h.Size = int64(len(e.body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("fixture header %s: %v", h.Name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
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
	return l
}

// capabilityXattr is a VFS_CAP_REVISION_2 security.capability value granting
// cap_net_raw (effective + permitted), as on iputils ping.
const capabilityXattr = "\x01\x00\x00\x02\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// specialModesFixture returns the two layers of a source image holding every
// kind of entry an unprivileged hardener cannot stage faithfully, and the
// expected source state after both layers are applied (path -> entry).
func specialModesFixture(t *testing.T) (layers []v1.Layer, final map[string]fixtureEntry) {
	t.Helper()
	elfPath := filepath.Join(t.TempDir(), "sudo")
	writeDynELF(t, elfPath, "libsudo_util.so.0")
	sudoELF, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}

	ping := fxFile("usr/bin/ping", 0o755, 0, 0, "ping")
	ping.hdr.PAXRecords = map[string]string{"SCHILY.xattr.security.capability": capabilityXattr}
	sudo := fxFile("usr/bin/sudo", 0o4111, 0, 0, string(sudoELF))
	sudo.hdr.Uname, sudo.hdr.Gname = "root", "root"

	l1 := []fixtureEntry{
		fxDir("etc/", 0o755, 0, 0),
		fxFile("etc/passwd", 0o644, 0, 0, "root:x:0:0::/root:/bin/sh\n"),
		fxFile("etc/group", 0o644, 0, 0, "root:x:0:\n"),
		fxFile("etc/shadow", 0o000, 0, 0, "root:!!::0:99999:7:::\n"),
		fxFile("etc/gshadow", 0o000, 0, 0, "root:::\n"),
		fxDir("usr/", 0o755, 0, 0),
		fxDir("usr/bin/", 0o755, 0, 0),
		sudo,
		{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "usr/bin/sudoedit", Linkname: "usr/bin/sudo", Mode: 0o4111, ModTime: fixtureTime}},
		ping,
		fxDir("usr/lib64/", 0o555, 0, 0),
		fxFile("usr/lib64/libsudo_util.so.0", 0o000, 0, 0, "not really a library"),
		fxDir("root/", 0o550, 0, 0),
		fxFile("root/.bashrc", 0o644, 0, 0, "# bashrc\n"),
		fxFile("root/gone", 0o600, 0, 0, "whited out by layer 2"),
		fxDir("root/sub/", 0o500, 0, 0),
		fxFile("root/sub/f", 0o400, 0, 0, "f"),
		fxDir("home/", 0o755, 0, 0),
		fxDir("home/app/", 0o700, 1000, 1000),
		fxFile("home/app/data", 0o640, 1000, 1000, "data"),
		fxDir("tmp/", 0o1777, 0, 0),
		fxDir("var/", 0o755, 0, 0),
		fxDir("var/empty/", 0o000, 0, 0),
		fxDir("dev/", 0o755, 0, 0),
		{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Mode: 0o666, Devmajor: 1, Devminor: 3, ModTime: fixtureTime}},
		{hdr: tar.Header{Typeflag: tar.TypeBlock, Name: "dev/sda", Mode: 0o660, Gid: 6, Devmajor: 8, Devminor: 0, ModTime: fixtureTime}},
		fxDir("run/", 0o755, 0, 0),
		{hdr: tar.Header{Typeflag: tar.TypeFifo, Name: "run/initctl", Mode: 0o600, Uid: 1000, Gid: 1000, ModTime: fixtureTime}},
	}
	l1[0].hdr.Uname = "root"
	// Layer 2 writes into the 0500 /root/sub and whites out a file of the
	// 0550 /root, as a later Dockerfile step would.
	l2 := []fixtureEntry{
		fxFile("root/sub/new", 0o000, 0, 0, "new in layer 2"),
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "root/.wh.gone", Mode: 0o600, ModTime: fixtureTime}},
	}

	final = map[string]fixtureEntry{}
	for _, e := range append(append([]fixtureEntry{}, l1...), l2...) {
		p := "/" + strings.TrimSuffix(e.hdr.Name, "/")
		if strings.HasPrefix(filepath.Base(p), ".wh.") {
			delete(final, filepath.Join(filepath.Dir(p), strings.TrimPrefix(filepath.Base(p), ".wh.")))
			continue
		}
		if e.hdr.Typeflag == tar.TypeLink {
			// A hard link is written as a regular file with its target's
			// metadata and content.
			tgt := final["/"+e.hdr.Linkname]
			tgt.hdr.Name = e.hdr.Name
			e = tgt
		}
		final[p] = e
	}
	return []v1.Layer{layerFromEntries(t, l1), layerFromEntries(t, l2)}, final
}

func pushLayers(t *testing.T, layers []v1.Layer) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	img, err := mutate.AppendLayers(empty.Image, layers...)
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
	ref := strings.TrimPrefix(srv.URL, "http://") + "/nonroot/special:latest"
	if err := crane.Push(img, ref, crane.Insecure); err != nil {
		t.Fatal(err)
	}
	return ref
}

// readOutputLayer returns every entry of the single layer of the image in the
// OCI layout outDir, keyed by "/"-rooted path.
func readOutputLayer(t *testing.T, outDir string) map[string]fixtureEntry {
	t.Helper()
	idx, err := layout.ImageIndexFromPath(outDir)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil || len(im.Manifests) != 1 {
		t.Fatalf("index manifest: %v", err)
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
	out := map[string]fixtureEntry{}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		p := "/" + strings.TrimSuffix(h.Name, "/")
		if _, dup := out[p]; dup {
			t.Errorf("%s written twice", p)
		}
		out[p] = fixtureEntry{hdr: *h, body: body}
	}
	return out
}

func xattrRecords(h tar.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h.PAXRecords {
		if strings.HasPrefix(k, "SCHILY.xattr.") {
			out[k] = v
		}
	}
	return out
}

func TestBuildImage_SpecialModes(t *testing.T) {
	layers, final := specialModesFixture(t)
	ref := pushLayers(t, layers)

	kept := []string{
		"/etc/shadow", "/etc/gshadow", "/usr/bin/sudo", "/usr/bin/sudoedit",
		"/usr/bin/ping", "/root/.bashrc", "/root/sub/f", "/root/sub/new",
		"/home/app/data", "/tmp", "/dev/null", "/dev/sda", "/run/initctl",
		"/root/gone", // whited out: must not reappear
	}
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{}}
	for _, p := range kept {
		m.Files[p] = manifest.FileEntry{Source: manifest.SourceDirect}
	}

	outDir := t.TempDir()
	res, err := BuildImage(t.Context(), ref, m, outDir, BuildOptions{
		Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true,
		WorkDir: t.TempDir(), RecordInventory: true,
	})
	if err != nil {
		t.Fatalf("BuildImage (euid %d): %v", os.Geteuid(), err)
	}
	t.Logf("euid=%d layer=%s files=%d inventory=%d", os.Geteuid(), res.LayerDigest, res.FileCount, len(res.Inventory))

	// The ELF resolver must read a mode 4111 binary and find its 0000
	// library in a 0555 directory.
	if e, ok := m.Files["/usr/lib64/libsudo_util.so.0"]; !ok || e.Source != manifest.SourceInferredELF {
		t.Errorf("DT_NEEDED of the 4111 binary not resolved: %+v (unresolved %v)", e, res.Unresolved)
	}

	got := readOutputLayer(t, outDir)
	want := []string{
		"/etc", "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group",
		"/usr", "/usr/bin", "/usr/bin/sudo", "/usr/bin/sudoedit", "/usr/bin/ping",
		"/usr/lib64", "/usr/lib64/libsudo_util.so.0",
		"/root", "/root/.bashrc", "/root/sub", "/root/sub/f", "/root/sub/new",
		"/home", "/home/app", "/home/app/data", "/tmp",
		"/dev", "/dev/null", "/dev/sda", "/run", "/run/initctl",
	}
	for _, p := range want {
		g, ok := got[p]
		if !ok {
			t.Errorf("%s missing from the hardened layer", p)
			continue
		}
		src := final[p]
		gh, sh := g.hdr, src.hdr
		if gh.Typeflag != sh.Typeflag {
			t.Errorf("%s: type %q, source %q", p, gh.Typeflag, sh.Typeflag)
		}
		if gh.Mode != sh.Mode {
			t.Errorf("%s: mode %#o, source %#o", p, gh.Mode, sh.Mode)
		}
		if gh.Uid != sh.Uid || gh.Gid != sh.Gid || gh.Uname != sh.Uname || gh.Gname != sh.Gname {
			t.Errorf("%s: owner %d:%d (%q:%q), source %d:%d (%q:%q)", p, gh.Uid, gh.Gid, gh.Uname, gh.Gname, sh.Uid, sh.Gid, sh.Uname, sh.Gname)
		}
		if !gh.ModTime.Equal(sh.ModTime) {
			t.Errorf("%s: mtime %v, source %v", p, gh.ModTime, sh.ModTime)
		}
		if gh.Devmajor != sh.Devmajor || gh.Devminor != sh.Devminor {
			t.Errorf("%s: device %d,%d, source %d,%d", p, gh.Devmajor, gh.Devminor, sh.Devmajor, sh.Devminor)
		}
		if gx, sx := xattrRecords(gh), xattrRecords(sh); !reflect.DeepEqual(gx, sx) {
			t.Errorf("%s: xattrs %q, source %q", p, gx, sx)
		}
		if !bytes.Equal(g.body, src.body) {
			t.Errorf("%s: content %q, source %q", p, g.body, src.body)
		}
	}
	if _, ok := got["/root/gone"]; ok {
		t.Error("/root/gone was whited out in the source but is in the hardened layer")
	}

	if res.InventoryErr != nil {
		t.Fatalf("inventory: %v", res.InventoryErr)
	}
	checkInventory(t, res.Inventory, map[string]invWant{
		"/var/empty":   {inSource: true, typ: "dir"},
		"/dev/null":    {inSource: true, inHardened: true, typ: "other", hType: "other"},
		"/run/initctl": {inSource: true, inHardened: true, typ: "other", hType: "other"},
		"/etc/shadow":  {inSource: true, inHardened: true, typ: "file", hType: "file"},
		"/root/gone":   {},
	})
}

// TestBuildImage_SpecialModesReproducible builds the fixture twice and checks
// the layer digest is stable (source mtimes, not staging times, are used).
func TestBuildImage_SpecialModesReproducible(t *testing.T) {
	layers, _ := specialModesFixture(t)
	ref := pushLayers(t, layers)
	var digests []v1.Hash
	for range 2 {
		m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
			"/etc/shadow":   {Source: manifest.SourceDirect},
			"/usr/bin/sudo": {Source: manifest.SourceDirect},
			"/dev/null":     {Source: manifest.SourceDirect},
		}}
		res, err := BuildImage(t.Context(), ref, m, t.TempDir(), BuildOptions{
			Platform: "linux/amd64", Keychain: NewKeychain(), Insecure: true, WorkDir: t.TempDir(),
		})
		if err != nil {
			t.Fatalf("BuildImage: %v", err)
		}
		digests = append(digests, res.LayerDigest)
	}
	if digests[0] != digests[1] {
		t.Errorf("layer digest differs between identical builds: %s vs %s", digests[0], digests[1])
	}
}

// TestExtractLayer_StagesUnprivileged checks the staging tree itself: every
// staged file is readable and every staged directory writable by the current
// user, special files are placeholders, and the metadata keeps the source
// values.
func TestExtractLayer_StagesUnprivileged(t *testing.T) {
	layers, final := specialModesFixture(t)
	dir := t.TempDir()
	meta := stagingMeta{}
	for _, l := range layers {
		if err := extractLayer(l, dir, nil, meta); err != nil {
			t.Fatalf("extractLayer: %v", err)
		}
	}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			if fi.Mode().Perm()&0o700 != 0o700 {
				t.Errorf("%s staged as %v: owner needs rwx", p, fi.Mode())
			}
		case fi.Mode().IsRegular():
			if fi.Mode().Perm()&0o600 != 0o600 {
				t.Errorf("%s staged as %v: owner needs rw", p, fi.Mode())
			}
			if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				t.Errorf("%s staged with setuid/setgid: %v", p, fi.Mode())
			}
		default:
			t.Errorf("%s staged as %v: only files, dirs and symlinks may be created", p, fi.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != len(final) {
		t.Errorf("metadata has %d paths, source state %d", len(meta), len(final))
	}
	for p, e := range final {
		sm, ok := meta[p]
		if !ok {
			t.Errorf("%s: no metadata", p)
			continue
		}
		if sm.Mode != e.hdr.Mode || sm.Uid != e.hdr.Uid || sm.Gid != e.hdr.Gid || sm.Typeflag != e.hdr.Typeflag {
			t.Errorf("%s: metadata %+v, source %+v", p, *sm, e.hdr)
		}
	}
	if _, ok := meta["/root/gone"]; ok {
		t.Error("whited-out path still has metadata")
	}
}
