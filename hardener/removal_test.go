package hardener

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// retained is a small helper to build a retained-path set from absolute paths.
func retained(paths ...string) map[string]struct{} {
	return RetainedSetFromKeys(paths)
}

func purls(removed []RemovedPackage) []string {
	out := make([]string, len(removed))
	for i, r := range removed {
		out[i] = r.Purl
	}
	return out
}

func TestComputeRemovedSet_fullyRemoved(t *testing.T) {
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/apt@2.6.1", Name: "apt", Version: "2.6.1",
			Paths: []string{"/usr/bin/apt", "/usr/lib/apt/methods/http"}},
	}
	// Nothing from apt was retained.
	got := ComputeRemovedSet(sources, retained("/usr/bin/nginx"))
	if len(got) != 1 {
		t.Fatalf("want 1 removed package, got %d", len(got))
	}
	if got[0].Purl != "pkg:deb/debian/apt@2.6.1" {
		t.Errorf("wrong purl: %s", got[0].Purl)
	}
	wantPaths := []string{"/usr/bin/apt", "/usr/lib/apt/methods/http"}
	if !reflect.DeepEqual(got[0].Paths, wantPaths) {
		t.Errorf("evidence paths = %v, want %v", got[0].Paths, wantPaths)
	}
}

func TestComputeRemovedSet_partialRetentionExcluded(t *testing.T) {
	// perl-base has two files; one of them is retained. R2: partial retention is
	// NOT removal — the package must be absent from the result.
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/perl-base@5.36.0-7", Name: "perl-base",
			Paths: []string{"/usr/bin/perl", "/usr/lib/perl-base/Config.pm"}},
	}
	got := ComputeRemovedSet(sources, retained("/usr/bin/perl"))
	if len(got) != 0 {
		t.Fatalf("partially-retained package must not be reported as removed, got %v", purls(got))
	}
}

func TestComputeRemovedSet_multiOwnerOneSurvives(t *testing.T) {
	// /shared/lib.so is owned by both pkgA and pkgB and is retained. Neither owner
	// may be reported removed, even though pkgA's other file is gone.
	shared := "/usr/lib/shared.so.1"
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/pkgA@1", Name: "pkgA", Paths: []string{shared, "/usr/bin/a-only"}},
		{Purl: "pkg:deb/debian/pkgB@2", Name: "pkgB", Paths: []string{shared}},
		{Purl: "pkg:deb/debian/pkgC@3", Name: "pkgC", Paths: []string{"/usr/bin/c-only"}},
	}
	got := ComputeRemovedSet(sources, retained(shared))
	// Only pkgC (no retained file) is removed.
	if !reflect.DeepEqual(purls(got), []string{"pkg:deb/debian/pkgC@3"}) {
		t.Fatalf("want only pkgC removed, got %v", purls(got))
	}
}

func TestComputeRemovedSet_emptyRemoval(t *testing.T) {
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/keepme@1", Paths: []string{"/usr/bin/keepme"}},
	}
	got := ComputeRemovedSet(sources, retained("/usr/bin/keepme"))
	if len(got) != 0 {
		t.Fatalf("want empty removed-set, got %v", purls(got))
	}
	// And a manifest built from it is still valid (non-nil, empty list).
	if got == nil {
		// ComputeRemovedSet returns a non-nil empty slice; document that contract.
		t.Errorf("ComputeRemovedSet should return non-nil empty slice")
	}
}

func TestComputeRemovedSet_zeroPathPackageSkipped(t *testing.T) {
	// A package syft cataloged without owned files (e.g. a language package) has
	// no file evidence and must never be reported removed.
	sources := []SourcePackage{
		{Purl: "pkg:npm/leftpad@1.0.0", Name: "leftpad"},
	}
	got := ComputeRemovedSet(sources, retained())
	if len(got) != 0 {
		t.Fatalf("zero-path package must be skipped, got %v", purls(got))
	}
}

func TestComputeRemovedSet_deterministicOrder(t *testing.T) {
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/zlib@1", Paths: []string{"/z"}},
		{Purl: "pkg:deb/debian/apt@1", Paths: []string{"/a"}},
		{Purl: "pkg:deb/debian/mawk@1", Paths: []string{"/m"}},
	}
	got := ComputeRemovedSet(sources, retained())
	want := []string{"pkg:deb/debian/apt@1", "pkg:deb/debian/mawk@1", "pkg:deb/debian/zlib@1"}
	if !reflect.DeepEqual(purls(got), want) {
		t.Fatalf("removed packages not sorted by purl: %v", purls(got))
	}
}

func TestComputeRemovedSet_pathNormalisationMatches(t *testing.T) {
	// Scanned path with a redundant component must still intersect a clean
	// retained key (and vice versa).
	sources := []SourcePackage{
		{Purl: "pkg:deb/debian/p@1", Paths: []string{"/usr/lib/./p/file"}},
	}
	got := ComputeRemovedSet(sources, retained("/usr/lib/p/file"))
	if len(got) != 0 {
		t.Fatalf("normalised paths should intersect; package wrongly removed: %v", purls(got))
	}
}

func TestParseSyftPackages(t *testing.T) {
	doc := `{
      "artifacts": [
        {
          "name": "apt", "version": "2.6.1", "type": "deb-package",
          "purl": "pkg:deb/debian/apt@2.6.1?arch=arm64",
          "metadata": { "files": [ {"path": "/usr/bin/apt"}, {"path": "/usr/lib/apt/methods/http"} ] }
        },
        {
          "name": "nofiles", "version": "9", "type": "deb-package",
          "purl": "pkg:deb/debian/nofiles@9",
          "metadata": {}
        },
        {
          "name": "no-purl", "version": "1", "type": "deb-package", "purl": "",
          "metadata": { "files": [ {"path": "/x"} ] }
        }
      ],
      "descriptor": { "name": "syft", "version": "1.18.1" }
    }`
	pkgs, syftVer, err := parseSyftPackages([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if syftVer != "1.18.1" {
		t.Errorf("syft version = %q, want 1.18.1", syftVer)
	}
	// no-purl artifact is dropped; apt + nofiles remain.
	if len(pkgs) != 2 {
		t.Fatalf("want 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	var apt *SourcePackage
	for i := range pkgs {
		if pkgs[i].Name == "apt" {
			apt = &pkgs[i]
		}
	}
	if apt == nil {
		t.Fatal("apt package not parsed")
	}
	wantPaths := []string{"/usr/bin/apt", "/usr/lib/apt/methods/http"}
	if !reflect.DeepEqual(apt.Paths, wantPaths) {
		t.Errorf("apt paths = %v, want %v", apt.Paths, wantPaths)
	}
}

func TestFilterOwnedFiles(t *testing.T) {
	root := t.TempDir()
	// A regular file, a shared directory, a symlink, all under root.
	mustWrite(t, filepath.Join(root, "usr/lib/libfoo.so.1"), "x")
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libfoo.so.1", filepath.Join(root, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}

	got := filterOwnedFiles(root, []string{
		"/usr",                 // dir — dropped (shared namespace)
		"/usr/lib",             // dir — dropped
		"/usr/lib/libfoo.so.1", // file — kept
		"/usr/lib/libfoo.so",   // symlink — kept
		"/usr/lib/missing.so",  // absent from source tree — dropped
	})
	want := []string{"/usr/lib/libfoo.so.1", "/usr/lib/libfoo.so"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterOwnedFiles = %v, want %v", got, want)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- schema conformance + drift guard ---------------------------------------

const removalSchemaDir = "../docs/removal-manifest-schema"

func removalSchemaPath() string {
	return filepath.Join(removalSchemaDir, "v1.schema.json")
}

func compileRemovalSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(removalSchemaPath())
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(removalSchemaPath(), doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	sch, err := c.Compile(removalSchemaPath())
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func validateRemoval(t *testing.T, sch *jsonschema.Schema, m *RemovalManifest) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse marshalled manifest: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("manifest does not conform to schema:\n%v\n\ndocument:\n%s", err, body)
	}
}

func newManifest(removed []RemovedPackage) *RemovalManifest {
	return &RemovalManifest{
		Schema:         RemovalManifestSchema,
		SchemaVersion:  RemovalManifestSchemaVersion,
		SourceDigest:   "sha256:" + str64('a'),
		SourcePlatform: "linux/arm64",
		HardenedDigest: "sha256:" + str64('b'),
		HardenedRef:    "localhost:5000/app-hardened@sha256:" + str64('b'),
		Tooling:        RemovalTooling{Hardener: "v0.1.1", Syft: "1.18.1"},
		Removed:        removed,
	}
}

func str64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func TestRemovalManifest_schemaConformance(t *testing.T) {
	sch := compileRemovalSchema(t)
	cases := map[string]*RemovalManifest{
		"empty": newManifest(ComputeRemovedSet(nil, retained())),
		"populated": newManifest(ComputeRemovedSet([]SourcePackage{
			{Purl: "pkg:deb/debian/apt@2.6.1?arch=arm64", Name: "apt", Version: "2.6.1",
				Paths: []string{"/usr/bin/apt"}},
		}, retained())),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) { validateRemoval(t, sch, m) })
	}
}

// publishedRemovalSchemaHashes freezes the sha256 of every published removal
// manifest JSON Schema. Once a version is published its file is IMMUTABLE: any
// edit changes the hash and fails this test (the mechanical half of the
// schema-drift guard, mirroring the profile schema). With the conformance test
// (additionalProperties:false), an un-versioned shape change cannot pass CI.
//
// To publish a new version: add v<N>.schema.json, bump the contract version,
// then record its hash here (`shasum -a 256 docs/removal-manifest-schema/*.json`).
var publishedRemovalSchemaHashes = map[string]string{
	"v1.schema.json": "e5ad49969e338bb6ae526db0a64a57950594f0ed72c9d20b9810ec7fdeedcaf6",
}

func TestRemovalSchemaDrift_publishedSchemasAreFrozen(t *testing.T) {
	for name, want := range publishedRemovalSchemaHashes {
		raw, err := os.ReadFile(filepath.Join(removalSchemaDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("published schema %s changed (hash %s, want %s).\n"+
				"Published removal-manifest schemas are immutable. A shape change requires a NEW "+
				"version file, a contract-version bump in lockstep with the controller, and a new "+
				"entry here — never an in-place edit.", name, got, want)
		}
	}
}

// TestRemovalSchemaDrift_currentVersionHasSchema ties the guard to the version
// the hardener emits.
func TestRemovalSchemaDrift_currentVersionHasSchema(t *testing.T) {
	if RemovalManifestSchemaVersion != "1.0" {
		t.Fatalf("RemovalManifestSchemaVersion is %q — add docs/removal-manifest-schema/v<N>.schema.json "+
			"and freeze its hash before bumping", RemovalManifestSchemaVersion)
	}
	if _, ok := publishedRemovalSchemaHashes["v1.schema.json"]; !ok {
		t.Fatal("v1.schema.json missing from publishedRemovalSchemaHashes")
	}
}
