package hardener

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// stageFiles creates the given paths (with parent dirs) under root with
// trivial content, mimicking an extracted source-image tree.
func stageFiles(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		abs := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func directEntry() manifest.FileEntry {
	return manifest.FileEntry{Source: manifest.SourceDirect, Count: 1}
}

func TestResolveRuntimeCompanions_PycAddsSiblingSource(t *testing.T) {
	root := t.TempDir()
	stageFiles(t, root,
		"/usr/local/lib/python3.12/encodings/__init__.py",
		"/usr/local/lib/python3.12/encodings/__pycache__/__init__.cpython-312.pyc",
	)

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/usr/local/lib/python3.12/encodings/__pycache__/__init__.cpython-312.pyc": directEntry(),
	}}

	added := ResolveRuntimeCompanions(root, m)

	want := "/usr/local/lib/python3.12/encodings/__init__.py"
	entry, ok := m.Files[want]
	if !ok {
		t.Fatalf("companion %s not added; added=%v", want, added)
	}
	if entry.Source != manifest.SourceInferredRuntime {
		t.Errorf("source = %q, want %q", entry.Source, manifest.SourceInferredRuntime)
	}
	if entry.InferredFrom != "/usr/local/lib/python3.12/encodings/__pycache__/__init__.cpython-312.pyc" {
		t.Errorf("InferredFrom = %q", entry.InferredFrom)
	}
	if len(added) != 1 || added[0] != want {
		t.Errorf("added = %v, want [%s]", added, want)
	}
}

func TestResolveRuntimeCompanions_OptLevelPyc(t *testing.T) {
	root := t.TempDir()
	stageFiles(t, root,
		"/app/lib/mod.py",
		"/app/lib/__pycache__/mod.cpython-311.opt-1.pyc",
	)

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/app/lib/__pycache__/mod.cpython-311.opt-1.pyc": directEntry(),
	}}

	ResolveRuntimeCompanions(root, m)

	if _, ok := m.Files["/app/lib/mod.py"]; !ok {
		t.Error("opt-1 pyc did not add sibling source")
	}
}

func TestResolveRuntimeCompanions_MissingSourceNotAdded(t *testing.T) {
	root := t.TempDir()
	// pyc exists in the image but the .py source genuinely does not
	// (sourceless distribution) — nothing must be invented.
	stageFiles(t, root, "/app/__pycache__/mod.cpython-312.pyc")

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/app/__pycache__/mod.cpython-312.pyc": directEntry(),
	}}

	added := ResolveRuntimeCompanions(root, m)

	if len(added) != 0 {
		t.Errorf("added = %v, want none", added)
	}
	if _, ok := m.Files["/app/mod.py"]; ok {
		t.Error("nonexistent source was added to manifest")
	}
}

func TestResolveRuntimeCompanions_TransientPycNormalized(t *testing.T) {
	root := t.TempDir()
	stageFiles(t, root,
		"/usr/local/lib/python3.12/contextvars.py",
		"/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc",
	)

	transient := "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc.252129543096560"
	final := "/usr/local/lib/python3.12/__pycache__/contextvars.cpython-312.pyc"

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		transient: directEntry(),
	}}

	ResolveRuntimeCompanions(root, m)

	if _, ok := m.Files[transient]; ok {
		t.Error("transient pyc entry not removed")
	}
	entry, ok := m.Files[final]
	if !ok {
		t.Fatal("final pyc not added from transient name")
	}
	if entry.Source != manifest.SourceInferredRuntime || entry.InferredFrom != transient {
		t.Errorf("final pyc entry = %+v", entry)
	}
	// The normalized pyc must feed rule 1 in the same pass.
	if _, ok := m.Files["/usr/local/lib/python3.12/contextvars.py"]; !ok {
		t.Error("sibling source of normalized pyc not added")
	}
}

func TestResolveRuntimeCompanions_TransientWithoutFinalDropped(t *testing.T) {
	root := t.TempDir()

	transient := "/app/__pycache__/gone.cpython-312.pyc.99999"
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		transient: directEntry(),
	}}

	added := ResolveRuntimeCompanions(root, m)

	if len(m.Files) != 0 || len(added) != 0 {
		t.Errorf("files=%v added=%v, want empty", m.Files, added)
	}
}

func TestResolveRuntimeCompanions_ExistingEntryNotOverwritten(t *testing.T) {
	root := t.TempDir()
	stageFiles(t, root,
		"/app/mod.py",
		"/app/__pycache__/mod.cpython-312.pyc",
	)

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/app/__pycache__/mod.cpython-312.pyc": directEntry(),
		"/app/mod.py":                          directEntry(), // already observed directly
	}}

	added := ResolveRuntimeCompanions(root, m)

	if len(added) != 0 {
		t.Errorf("added = %v, want none", added)
	}
	if m.Files["/app/mod.py"].Source != manifest.SourceDirect {
		t.Error("direct observation was downgraded")
	}
}

func TestResolveRuntimeCompanions_NonPythonPathsUntouched(t *testing.T) {
	root := t.TempDir()
	stageFiles(t, root, "/etc/nginx/nginx.conf", "/usr/lib/libc.so.6")

	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{
		"/etc/nginx/nginx.conf": directEntry(),
		"/usr/lib/libc.so.6":    directEntry(),
	}}

	added := ResolveRuntimeCompanions(root, m)

	if len(added) != 0 || len(m.Files) != 2 {
		t.Errorf("non-Python manifest changed: added=%v files=%d", added, len(m.Files))
	}
}
