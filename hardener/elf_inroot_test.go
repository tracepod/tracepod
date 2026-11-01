package hardener

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// These tests build synthetic image roots whose symlinks only make sense when
// resolved against the image root, never against the machine running the
// tests. Every absolute link target (/usr/lib/...) points at a path that does
// not exist on the host, so a resolver that follows links with the host's
// view of "/" cannot find the library at all.

func mkRoot(t *testing.T, dirs ...string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func link(t *testing.T, root, target, name string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
}

func seedManifest(paths ...string) *manifest.Manifest {
	now := time.Now()
	m := &manifest.Manifest{SchemaVersion: manifest.SchemaVersion, Files: map[string]manifest.FileEntry{}}
	for _, p := range paths {
		m.Files[p] = manifest.FileEntry{Source: manifest.SourceDirect, FirstSeen: now, LastSeen: now, Count: 1}
	}
	return m
}

func requireFiles(t *testing.T, m *manifest.Manifest, want ...string) {
	t.Helper()
	for _, w := range want {
		if _, ok := m.Files[w]; !ok {
			t.Errorf("manifest missing %s; have %v", w, keys(m))
		}
	}
}

func keys(m *manifest.Manifest) []string {
	out := make([]string, 0, len(m.Files))
	for k := range m.Files {
		out = append(out, k)
	}
	return out
}

// The library behind the symlink chain depends on libtracepodtest.so.9, which
// is discoverable only by reading the in-root copy of the library.
func TestResolveELF_AbsoluteSymlinkChain(t *testing.T) {
	root := mkRoot(t, "usr/bin", "usr/lib")
	writeDynELF(t, filepath.Join(root, "usr/bin/app"), "libfoo.so.1")
	writeDynELF(t, filepath.Join(root, "usr/lib/libfoo.so.1.2.3"), "libtracepodtest.so.9")
	writeDynELF(t, filepath.Join(root, "usr/lib/libtracepodtest.so.9"))
	link(t, root, "/usr/lib/libfoo.so.1.2.3", "usr/lib/libfoo.so.1.2")
	link(t, root, "/usr/lib/libfoo.so.1.2", "usr/lib/libfoo.so.1")

	m := seedManifest("/usr/bin/app")
	_, unresolved, err := ResolveELFDependencies(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved: %v", unresolved)
	}
	requireFiles(t, m, "/usr/lib/libfoo.so.1", "/usr/lib/libfoo.so.1.2.3", "/usr/lib/libtracepodtest.so.9")
}

func TestResolveELF_RelativeSymlinkChain(t *testing.T) {
	root := mkRoot(t, "usr/bin", "usr/lib/real")
	writeDynELF(t, filepath.Join(root, "usr/bin/app"), "libfoo.so.1")
	writeDynELF(t, filepath.Join(root, "usr/lib/real/libfoo.so.1.2.3"), "libtracepodtest.so.9")
	writeDynELF(t, filepath.Join(root, "usr/lib/libtracepodtest.so.9"))
	link(t, root, "real/libfoo.so.1.2.3", "usr/lib/libfoo.so.1.2")
	link(t, root, "libfoo.so.1.2", "usr/lib/libfoo.so.1")

	m := seedManifest("/usr/bin/app")
	_, unresolved, err := ResolveELFDependencies(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved: %v", unresolved)
	}
	requireFiles(t, m, "/usr/lib/libfoo.so.1", "/usr/lib/real/libfoo.so.1.2.3", "/usr/lib/libtracepodtest.so.9")
}

// Merged-usr: /lib and /bin are directory symlinks. Absolute and relative
// spellings must both resolve inside the root.
func TestResolveELF_DirectorySymlinkMidPath(t *testing.T) {
	for name, tgt := range map[string]struct{ lib, bin string }{
		"absolute": {"/usr/lib", "/usr/bin"},
		"relative": {"usr/lib", "usr/bin"},
	} {
		t.Run(name, func(t *testing.T) {
			root := mkRoot(t, "usr/bin", "usr/lib")
			link(t, root, tgt.lib, "lib")
			link(t, root, tgt.bin, "bin")
			writeDynELF(t, filepath.Join(root, "usr/bin/app"), "libfoo.so.1")
			writeDynELF(t, filepath.Join(root, "usr/lib/libfoo.so.1"), "libtracepodtest.so.9")
			writeDynELF(t, filepath.Join(root, "usr/lib/libtracepodtest.so.9"))

			// The seed is reached through the /bin directory symlink.
			m := seedManifest("/bin/app")
			_, unresolved, err := ResolveELFDependencies(root, m)
			if err != nil {
				t.Fatal(err)
			}
			if len(unresolved) != 0 {
				t.Errorf("unresolved: %v", unresolved)
			}
			requireFiles(t, m, "/lib/libfoo.so.1", "/usr/lib/libfoo.so.1", "/lib/libtracepodtest.so.9")
		})
	}
}

func TestResolveELF_SymlinkLoopIsBounded(t *testing.T) {
	root := mkRoot(t, "usr/bin", "usr/lib")
	writeDynELF(t, filepath.Join(root, "usr/bin/app"), "libself.so.1", "libping.so.1")
	link(t, root, "libself.so.1", "usr/lib/libself.so.1")
	link(t, root, "libpong.so.1", "usr/lib/libping.so.1")
	link(t, root, "libping.so.1", "usr/lib/libpong.so.1")

	done := make(chan struct{})
	var unresolved []string
	var err error
	go func() {
		defer close(done)
		_, unresolved, err = ResolveELFDependencies(root, seedManifest("/usr/bin/app"))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resolver did not terminate on a symlink loop")
	}
	if err != nil {
		t.Fatal(err)
	}
	// A looping library cannot be loaded, so it must be reported, not
	// silently treated as found.
	if len(unresolved) != 2 {
		t.Errorf("want both looping libs unresolved, got %v", unresolved)
	}
}

// ".." in a link target cannot climb above the image root.
func TestResolveELF_DotDotClampedAtRoot(t *testing.T) {
	root := mkRoot(t, "usr/bin", "usr/lib")
	writeDynELF(t, filepath.Join(root, "usr/bin/app"), "libfoo.so.1")
	writeDynELF(t, filepath.Join(root, "usr/lib/libfoo.so.1.2.3"), "libtracepodtest.so.9")
	writeDynELF(t, filepath.Join(root, "usr/lib/libtracepodtest.so.9"))
	link(t, root, "../../../../../../../usr/lib/libfoo.so.1.2.3", "usr/lib/libfoo.so.1")

	m := seedManifest("/usr/bin/app")
	_, unresolved, err := ResolveELFDependencies(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved: %v", unresolved)
	}
	requireFiles(t, m, "/usr/lib/libfoo.so.1", "/usr/lib/libfoo.so.1.2.3", "/usr/lib/libtracepodtest.so.9")
}

func TestExpandSymlinkTargets_DirectorySymlinkInPath(t *testing.T) {
	root := mkRoot(t, "usr/lib")
	link(t, root, "/usr/lib", "lib") // absolute directory symlink
	writeDynELF(t, filepath.Join(root, "usr/lib/libz.so.1"))
	link(t, root, "libz.so.1", "usr/lib/libz.so")

	m := seedManifest("/lib/libz.so")
	expandSymlinkTargets(m, root)
	requireFiles(t, m, "/lib/libz.so.1")
}

func TestExpandSymlinkTargets_AbsoluteTargetThroughDirSymlink(t *testing.T) {
	root := mkRoot(t, "usr/lib", "opt")
	link(t, root, "/usr/lib", "lib")
	writeDynELF(t, filepath.Join(root, "usr/lib/libz.so.1"))
	link(t, root, "/lib/libz.so.1", "opt/libz.so")

	m := seedManifest("/opt/libz.so")
	expandSymlinkTargets(m, root)
	requireFiles(t, m, "/lib/libz.so.1")
}

func TestResolveRuntimeCompanions_DirectorySymlinkInPath(t *testing.T) {
	root := mkRoot(t, "usr/lib/py/__pycache__")
	link(t, root, "/usr/lib", "lib")
	if err := os.WriteFile(filepath.Join(root, "usr/lib/py/mod.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := seedManifest("/lib/py/__pycache__/mod.cpython-312.pyc")
	ResolveRuntimeCompanions(root, m)
	requireFiles(t, m, "/lib/py/mod.py")
}

func TestWriteTarEntries_DirectorySymlinkInPath(t *testing.T) {
	root := mkRoot(t, "usr/lib")
	link(t, root, "/usr/lib", "lib")
	if err := os.WriteFile(filepath.Join(root, "usr/lib/libfoo.so.1"), []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := seedManifest("/lib/libfoo.so.1")

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarEntries(tw, m, root); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			t.Fatal("lib/libfoo.so.1 missing from layer")
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "lib/libfoo.so.1" {
			b, _ := io.ReadAll(tr)
			if string(b) != "payload" {
				t.Errorf("wrong content %q", b)
			}
			return
		}
	}
}
