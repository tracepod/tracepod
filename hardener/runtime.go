package hardener

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// Language-runtime companion rules.
//
// The sensor observes openat/exec/mmap — it cannot see files an interpreter
// merely stat(2)s. CPython is the acute case: importing a module with a fresh
// bytecode cache stats <pkg>/<mod>.py (never opens it) and opens only
// <pkg>/__pycache__/<mod>.cpython-NN.pyc. At runtime, however, CPython ignores
// a __pycache__ pyc whose sibling source is missing, so an image built from
// exactly the observed paths cannot even `import encodings` and dies in
// interpreter startup (init_fs_encoding). ResolveRuntimeCompanions closes that
// gap deterministically: every rule adds only files that exist in the source
// image, with a full audit trail (source=inferred-runtime, InferredFrom).

// pycacheRe matches a bytecode cache path and captures the package directory
// and module stem: <pkg>/__pycache__/<stem>.cpython-NN[.opt-1|.opt-2].pyc
var pycacheRe = regexp.MustCompile(`^(.*)/__pycache__/([^/.]+)\.cpython-\d+(?:\.opt-[12])?\.pyc$`)

// transientPycRe matches CPython's atomic-write temporary names: the importer
// writes <mod>.cpython-NN.pyc.<random-digits> and renames it over the final
// path. The sensor records the temporary name; the source image only ever
// contains the final one.
var transientPycRe = regexp.MustCompile(`^(.+\.pyc)\.\d+$`)

// ResolveRuntimeCompanions applies runtime companion rules to the manifest
// against the extracted source-image tree rooted at extractedDir. It returns
// the manifest paths it added. Rules:
//
//  1. pyc → py: for every __pycache__ bytecode entry, add the sibling source
//     file (<pkg>/<stem>.py) when it exists in the source image.
//  2. transient pyc: rewrite atomic-write temp names (<path>.pyc.<digits>) to
//     <path>.pyc when the final path exists; the temp entry is dropped either
//     way (it cannot exist in the source image). The rewritten pyc then feeds
//     rule 1 like any other bytecode entry.
func ResolveRuntimeCompanions(extractedDir string, m *manifest.Manifest) (added []string) {
	now := time.Now().UTC()

	addEntry := func(path, inferredFrom string) {
		if _, exists := m.Files[path]; exists {
			return
		}
		m.Files[path] = manifest.FileEntry{
			Source:       manifest.SourceInferredRuntime,
			AccessModes:  []manifest.AccessMode{},
			FirstSeen:    now,
			LastSeen:     now,
			Count:        0,
			InferredFrom: inferredFrom,
		}
		added = append(added, path)
	}

	existsInImage := func(path string) bool {
		_, err := os.Lstat(filepath.Join(extractedDir, path))
		return err == nil
	}

	// Rule 2 first, so a normalized pyc is visible to rule 1 in the same pass.
	var transient []string
	for path := range m.Files {
		if transientPycRe.MatchString(path) {
			transient = append(transient, path)
		}
	}
	for _, path := range transient {
		entry := m.Files[path]
		delete(m.Files, path)
		final := transientPycRe.FindStringSubmatch(path)[1]
		if !existsInImage(final) {
			continue
		}
		if _, exists := m.Files[final]; exists {
			continue
		}
		// Preserve the original observation: the final pyc is the same file the
		// runtime opened under its temporary name.
		entry.InferredFrom = path
		if entry.Source == manifest.SourceDirect {
			entry.Source = manifest.SourceInferredRuntime
		}
		m.Files[final] = entry
		added = append(added, final)
	}

	// Rule 1: bytecode cache implies its sibling source file.
	var caches []string
	for path := range m.Files {
		if pycacheRe.MatchString(path) {
			caches = append(caches, path)
		}
	}
	for _, path := range caches {
		mm := pycacheRe.FindStringSubmatch(path)
		src := mm[1] + "/" + mm[2] + ".py"
		if !strings.HasPrefix(src, "/") || !existsInImage(src) {
			continue
		}
		addEntry(src, path)
	}

	return added
}
