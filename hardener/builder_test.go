package hardener

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/tracepod/tracepod/manifest"
)

// --- buildConfigFile tests ---

func TestBuildConfig_PreservesRuntimeFields(t *testing.T) {
	src := &v1.ConfigFile{
		Config: v1.Config{
			Entrypoint: []string{"/usr/sbin/nginx", "-g", "daemon off;"},
			Cmd:        []string{"--help"},
			User:       "1000:1000",
			Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin"},
			WorkingDir: "/var/www",
			ExposedPorts: map[string]struct{}{
				"80/tcp": {},
			},
			Volumes: map[string]struct{}{
				"/data": {},
			},
			StopSignal: "SIGQUIT",
		},
		OS:           "linux",
		Architecture: "amd64",
	}
	base := &v1.ConfigFile{}
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{}}

	out := buildConfigFile(base, src, m, "nginx:latest", "sha256:abc")

	if got := out.Config.Entrypoint; len(got) == 0 || got[0] != "/usr/sbin/nginx" {
		t.Errorf("Entrypoint = %v, want [/usr/sbin/nginx ...]", got)
	}
	if got := out.Config.Cmd; len(got) == 0 || got[0] != "--help" {
		t.Errorf("Cmd = %v, want [--help]", got)
	}
	if got := out.Config.User; got != "1000:1000" {
		t.Errorf("User = %q, want 1000:1000", got)
	}
	if got := out.Config.WorkingDir; got != "/var/www" {
		t.Errorf("WorkingDir = %q, want /var/www", got)
	}
	if got := out.Config.StopSignal; got != "SIGQUIT" {
		t.Errorf("StopSignal = %q, want SIGQUIT", got)
	}
	if _, ok := out.Config.ExposedPorts["80/tcp"]; !ok {
		t.Error("ExposedPorts[80/tcp] missing")
	}
	if _, ok := out.Config.Volumes["/data"]; !ok {
		t.Error("Volumes[/data] missing")
	}
	if got := out.OS; got != "linux" {
		t.Errorf("OS = %q, want linux", got)
	}
	if got := out.Architecture; got != "amd64" {
		t.Errorf("Architecture = %q, want amd64", got)
	}
}

func TestBuildConfig_DropsOnBuild(t *testing.T) {
	src := &v1.ConfigFile{
		Config: v1.Config{
			OnBuild: []string{"RUN echo build-time-only", "COPY . ."},
		},
	}
	out := buildConfigFile(&v1.ConfigFile{}, src, &manifest.Manifest{Files: map[string]manifest.FileEntry{}}, "img:latest", "sha256:abc")
	if len(out.Config.OnBuild) != 0 {
		t.Errorf("OnBuild should be nil/empty after strip, got %v", out.Config.OnBuild)
	}
}

func TestBuildConfig_SingleHistoryEntry(t *testing.T) {
	src := &v1.ConfigFile{}
	for i := 0; i < 5; i++ {
		src.History = append(src.History, v1.History{CreatedBy: fmt.Sprintf("layer %d", i)})
	}
	out := buildConfigFile(&v1.ConfigFile{}, src, &manifest.Manifest{Files: map[string]manifest.FileEntry{}}, "img:latest", "sha256:abc")
	if len(out.History) != 1 {
		t.Errorf("History len = %d, want exactly 1", len(out.History))
	}
	if got := out.History[0].CreatedBy; got != "tracepod hardener (M5)" {
		t.Errorf("History[0].CreatedBy = %q, want tracepod hardener (M5)", got)
	}
}

func TestBuildConfig_ProvenanceLabels(t *testing.T) {
	m := &manifest.Manifest{
		ProfileStart: time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		ProfileEnd:   time.Date(2026, 4, 1, 10, 1, 0, 0, time.UTC),
		Files: map[string]manifest.FileEntry{
			"/usr/bin/app": {Source: manifest.SourceDirect},
		},
	}
	out := buildConfigFile(&v1.ConfigFile{}, &v1.ConfigFile{}, m, "nginx:1.25-alpine", "sha256:deadbeef")

	required := []string{
		"com.tracepod.source-image",
		"com.tracepod.source-digest",
		"com.tracepod.manifest-hash",
		"com.tracepod.profile-start",
		"com.tracepod.profile-end",
		"com.tracepod.build-time",
	}
	for _, k := range required {
		if v, ok := out.Config.Labels[k]; !ok || v == "" {
			t.Errorf("label %q missing or empty (got %q)", k, v)
		}
	}
	if got := out.Config.Labels["com.tracepod.source-image"]; got != "nginx:1.25-alpine" {
		t.Errorf("source-image label = %q, want nginx:1.25-alpine", got)
	}
	if got := out.Config.Labels["com.tracepod.source-digest"]; got != "sha256:deadbeef" {
		t.Errorf("source-digest label = %q, want sha256:deadbeef", got)
	}
}

func TestBuildConfig_MergesLabels(t *testing.T) {
	src := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"original-key":              "original-val",
				"com.tracepod.source-image": "should-be-overwritten",
			},
		},
	}
	m := &manifest.Manifest{Files: map[string]manifest.FileEntry{}}
	out := buildConfigFile(&v1.ConfigFile{}, src, m, "img:latest", "sha256:abc")

	if got := out.Config.Labels["original-key"]; got != "original-val" {
		t.Errorf("original label lost: got %q, want original-val", got)
	}
	// tracepod label should overwrite the source value
	if got := out.Config.Labels["com.tracepod.source-image"]; got != "img:latest" {
		t.Errorf("tracepod label not overwritten: got %q, want img:latest", got)
	}
}

func TestBuildConfig_PreservesRootFSDiffIDs(t *testing.T) {
	base := &v1.ConfigFile{
		RootFS: v1.RootFS{
			Type:    "layers",
			DiffIDs: []v1.Hash{{Algorithm: "sha256", Hex: "abc123"}},
		},
	}
	out := buildConfigFile(base, &v1.ConfigFile{}, &manifest.Manifest{Files: map[string]manifest.FileEntry{}}, "img:latest", "sha256:abc")
	if len(out.RootFS.DiffIDs) != 1 || out.RootFS.DiffIDs[0].Hex != "abc123" {
		t.Errorf("RootFS DiffIDs not preserved: got %v", out.RootFS.DiffIDs)
	}
}

// --- checkScratchCompat tests ---

func createFile(t *testing.T, root, path string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func createSymlink(t *testing.T, root, path, target string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		t.Fatal(err)
	}
}

func emptyManifest() *manifest.Manifest {
	return &manifest.Manifest{Files: make(map[string]manifest.FileEntry)}
}

func TestCheckScratchCompat_AllPresent(t *testing.T) {
	dir := t.TempDir()
	m := emptyManifest()

	for _, path := range []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/nsswitch.conf",
		"/etc/resolv.conf",
		"/etc/ssl/certs/ca-certificates.crt",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", // first glibc candidate wins
	} {
		createFile(t, dir, path)
	}

	warnings := checkScratchCompat(m, dir, "amd64")
	if len(warnings) != 0 {
		t.Errorf("want 0 warnings when all files present, got %d: %v", len(warnings), warnings)
	}
	// All paths should now be in the manifest.
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		if _, ok := m.Files[path]; !ok {
			t.Errorf("expected %s in manifest after scratch compat check", path)
		}
	}
}

func TestCheckScratchCompat_MissingPasswd(t *testing.T) {
	dir := t.TempDir()
	m := emptyManifest()

	// Create everything except /etc/passwd
	for _, path := range []string{
		"/etc/group",
		"/etc/nsswitch.conf",
		"/etc/resolv.conf",
		"/etc/ssl/certs/ca-certificates.crt",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	} {
		createFile(t, dir, path)
	}

	warnings := checkScratchCompat(m, dir, "amd64")
	found := false
	for _, w := range warnings {
		if contains(w, "/etc/passwd") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about /etc/passwd missing, got: %v", warnings)
	}
}

func TestCheckScratchCompat_ResolvConfMissing(t *testing.T) {
	dir := t.TempDir()
	m := emptyManifest()

	// All files present except resolv.conf (common: it's bind-mounted).
	for _, path := range []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/nsswitch.conf",
		"/etc/ssl/certs/ca-certificates.crt",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	} {
		createFile(t, dir, path)
	}

	warnings := checkScratchCompat(m, dir, "amd64")
	found := false
	for _, w := range warnings {
		if contains(w, "/etc/resolv.conf") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected resolv.conf warning, got: %v", warnings)
	}
	// resolv.conf warning should mention bind-mount so the user isn't alarmed.
	for _, w := range warnings {
		if contains(w, "/etc/resolv.conf") && !contains(w, "bind-mounted") {
			t.Errorf("resolv.conf warning should mention bind-mounted, got: %q", w)
		}
	}
}

func TestCheckScratchCompat_CertDirFallback(t *testing.T) {
	dir := t.TempDir()
	m := emptyManifest()

	// No ca-certificates.crt bundle, but individual certs exist in the dir.
	for _, path := range []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/nsswitch.conf",
		"/etc/resolv.conf",
		"/etc/ssl/certs/cert1.pem",
		"/etc/ssl/certs/cert2.pem",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	} {
		createFile(t, dir, path)
	}

	warnings := checkScratchCompat(m, dir, "amd64")

	// Should not warn about certs (directory fallback succeeded).
	for _, w := range warnings {
		if contains(w, "ca-certificates") {
			t.Errorf("unexpected cert warning when dir fallback succeeds: %q", w)
		}
	}
	// Individual cert files should be in manifest.
	for _, path := range []string{"/etc/ssl/certs/cert1.pem", "/etc/ssl/certs/cert2.pem"} {
		if _, ok := m.Files[path]; !ok {
			t.Errorf("expected %s in manifest after cert dir fallback", path)
		}
	}
}

func TestCheckScratchCompat_ExistingEntryNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/etc/passwd")

	// Pre-populate with a direct observation entry.
	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/etc/passwd": {Source: manifest.SourceDirect, Count: 5},
		},
	}
	checkScratchCompat(m, dir, "amd64")

	// Direct entry must not be replaced by manual/scratch-compat.
	entry := m.Files["/etc/passwd"]
	if entry.Source != manifest.SourceDirect {
		t.Errorf("existing direct entry overwritten: source = %q", entry.Source)
	}
	if entry.Count != 5 {
		t.Errorf("existing entry count changed: %d", entry.Count)
	}
}

// --- buildLayer / writeTarEntries tests ---

func TestBuildLayer_DeterministicOutput(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/usr/bin/app")
	createFile(t, dir, "/lib/libc.so.6")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/bin/app":   {Source: manifest.SourceDirect},
			"/lib/libc.so.6": {Source: manifest.SourceInferredELF},
		},
	}

	read := func() []byte {
		rc, err := buildLayer(m, dir)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	b1 := read()
	b2 := read()

	if !bytes.Equal(b1, b2) {
		t.Error("buildLayer output is not deterministic across two calls")
	}
}

func TestBuildLayer_OmitsUnlistedFiles(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/usr/bin/app")
	createFile(t, dir, "/usr/bin/extra") // not in manifest

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/bin/app": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	for _, name := range names {
		if name == "usr/bin/extra" || name == "usr/bin/extra/" {
			t.Errorf("unlisted file %q present in tar layer", name)
		}
	}
}

func TestBuildLayer_PreservesSymlinks(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/lib/libfoo.so.1.2.3")
	createSymlink(t, dir, "/lib/libfoo.so.1", "libfoo.so.1.2.3")
	createSymlink(t, dir, "/lib/libfoo.so", "libfoo.so.1")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/lib/libfoo.so.1.2.3": {Source: manifest.SourceDirect},
			"/lib/libfoo.so.1":     {Source: manifest.SourceInferredELF},
			"/lib/libfoo.so":       {Source: manifest.SourceInferredELF},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	symlinks := tarSymlinks(t, rc)
	if _, ok := symlinks["lib/libfoo.so.1"]; !ok {
		t.Error("symlink lib/libfoo.so.1 not present in tar")
	}
	if got := symlinks["lib/libfoo.so.1"]; got != "libfoo.so.1.2.3" {
		t.Errorf("lib/libfoo.so.1 target = %q, want libfoo.so.1.2.3", got)
	}
}

func TestBuildLayer_SkipsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/usr/bin/present")
	// /usr/bin/absent is in the manifest but does not exist on disk (ENOENT probe).

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/bin/present": {Source: manifest.SourceDirect},
			"/usr/bin/absent":  {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	for _, name := range names {
		if name == "usr/bin/absent" {
			t.Error("absent file present in tar layer — should be silently skipped")
		}
	}
}

func TestBuildLayer_SynthesisesParentDirs(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/usr/sbin/nginx")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/sbin/nginx": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	wantDirs := []string{"usr/", "usr/sbin/"}
	for _, want := range wantDirs {
		found := false
		for _, name := range names {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("parent dir %q not synthesised in tar (entries: %v)", want, names)
		}
	}
}

// --- helpers ---

// tarEntryNames decompresses a gzip tar stream and returns all entry names.
func tarEntryNames(t *testing.T, rc io.Reader) []string {
	t.Helper()
	gr, err := gzip.NewReader(rc)
	if err != nil {
		t.Fatal("gzip.NewReader:", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("tar.Next:", err)
		}
		names = append(names, hdr.Name)
	}
	return names
}

// tarSymlinks returns a map of symlink name → target from a gzip tar stream.
func tarSymlinks(t *testing.T, rc io.Reader) map[string]string {
	t.Helper()
	gr, err := gzip.NewReader(rc)
	if err != nil {
		t.Fatal("gzip.NewReader:", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	out := make(map[string]string)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("tar.Next:", err)
		}
		if hdr.Typeflag == tar.TypeSymlink {
			out[hdr.Name] = hdr.Linkname
		}
	}
	return out
}

// TestBuildLayer_SkipsENOTDIRPaths verifies that paths where a file is used as
// a directory component (e.g. "foo.php/.htaccess" where foo.php is a regular
// file) are silently skipped rather than causing a fatal error.  This mirrors
// what Apache emits: it probes "foo.php/.htaccess" via openat() even though
// the kernel will return ENOTDIR — the sensor records the probe, so the
// hardener must handle it gracefully.
func TestBuildLayer_SkipsENOTDIRPaths(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file where the manifest also references a "child" path.
	createFile(t, dir, "/var/www/html/healthz.php")
	createFile(t, dir, "/var/www/html/index.php")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/var/www/html/index.php":           {Source: manifest.SourceDirect},
			"/var/www/html/healthz.php":         {Source: manifest.SourceDirect},
			// This path has healthz.php as a directory component — must be skipped.
			"/var/www/html/healthz.php/.htaccess": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatalf("buildLayer returned error on ENOTDIR path: %v", err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	for _, name := range names {
		if name == "var/www/html/healthz.php/.htaccess" {
			t.Errorf("ENOTDIR path %q must not appear in tar layer", name)
		}
	}
}

// TestBuildLayer_SymlinkTargetIncluded verifies that when a manifest contains
// a symlink (e.g. python → python3) but not its target, buildLayer includes
// the resolved target in the tar layer.  This is the root cause of the
// python-hello sandbox failure: exec "python" failed because python3 was absent.
func TestBuildLayer_SymlinkTargetIncluded(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/usr/local/bin/python3")
	createSymlink(t, dir, "/usr/local/bin/python", "python3")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			// Manifest only has the symlink; target is absent.
			"/usr/local/bin/python": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatalf("buildLayer returned error: %v", err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	for _, name := range names {
		if name == "usr/local/bin/python3" {
			return // found — pass
		}
	}
	t.Errorf("symlink target python3 not found in tar layer; entries: %v", names)
}

// TestBuildLayer_RelativeSymlinkTargetInSameDir verifies that a relative
// sibling symlink (libz.so.1 → libz.so.1.3.1) causes the versioned file to
// be included even when only the symlink appears in the manifest.  This is the
// root cause of the ruby-hello sandbox failure: libz.so.1 pointed to a sibling
// that was never added to the tar.
func TestBuildLayer_RelativeSymlinkTargetInSameDir(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/lib/aarch64-linux-gnu/libz.so.1.3.1")
	createSymlink(t, dir, "/lib/aarch64-linux-gnu/libz.so.1", "libz.so.1.3.1")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/lib/aarch64-linux-gnu/libz.so.1": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatalf("buildLayer returned error: %v", err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	for _, name := range names {
		if name == "lib/aarch64-linux-gnu/libz.so.1.3.1" {
			return // found — pass
		}
	}
	t.Errorf("symlink target libz.so.1.3.1 not in tar layer; entries: %v", names)
}

// TestBuildLayer_SymlinkChainIncluded verifies that a two-hop symlink chain
// (libfoo.so → libfoo.so.1 → libfoo.so.1.2.3) causes all intermediate and
// final targets to be included when only the first symlink is in the manifest.
func TestBuildLayer_SymlinkChainIncluded(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "/lib/libfoo.so.1.2.3")
	createSymlink(t, dir, "/lib/libfoo.so.1", "libfoo.so.1.2.3")
	createSymlink(t, dir, "/lib/libfoo.so", "libfoo.so.1")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			// Only the outermost symlink is in the manifest.
			"/lib/libfoo.so": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatalf("buildLayer returned error: %v", err)
	}
	defer rc.Close()

	names := tarEntryNames(t, rc)
	wantAll := []string{"lib/libfoo.so.1", "lib/libfoo.so.1.2.3"}
	for _, want := range wantAll {
		found := false
		for _, name := range names {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in tar layer (symlink chain); entries: %v", want, names)
		}
	}
}

// TestBuildLayer_BrokenSymlinkSkipped verifies that a symlink whose target
// is absent from the staging directory does not cause a fatal error.
func TestBuildLayer_BrokenSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	// Only the symlink exists; the target does not.
	createSymlink(t, dir, "/usr/local/bin/python", "python3")

	m := &manifest.Manifest{
		Files: map[string]manifest.FileEntry{
			"/usr/local/bin/python": {Source: manifest.SourceDirect},
		},
	}

	rc, err := buildLayer(m, dir)
	if err != nil {
		t.Fatalf("buildLayer returned error on broken symlink: %v", err)
	}
	rc.Close()
}

// contains reports whether s contains sub.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- BuildImage integration tests (network) ---

// nginxMinimalManifest returns a minimal manifest seeded with /usr/sbin/nginx
// as a direct observation. BuildImage's ELF resolver and scratch-compat injector
// will expand this to the full set of dependencies.
func nginxMinimalManifest() *manifest.Manifest {
	now := time.Now()
	start := now.Add(-15 * time.Minute) // long-enough window to avoid short-window penalty
	return &manifest.Manifest{
		SchemaVersion: "1",
		ContainerID:   "test-build",
		ProfileStart:  start,
		ProfileEnd:    now,
		Files: map[string]manifest.FileEntry{
			"/usr/sbin/nginx": {
				Source:      manifest.SourceDirect,
				AccessModes: []manifest.AccessMode{manifest.AccessExecute},
				FirstSeen:   start,
				LastSeen:    now,
				Count:       3,
			},
		},
	}
}

// TestBuildImage_NginxAlpine is a full-pipeline integration test: pulls
// nginx:1.25-alpine, resolves ELF dependencies, assembles a FROM-scratch OCI
// layout, and verifies the result is valid.
//
// Requires network access; skipped in short mode.
func TestBuildImage_NginxAlpine(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	result, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform: "linux/amd64",
			Keychain: NewKeychain(),
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	// OCI layout must be written.
	if _, err := os.Stat(filepath.Join(outputDir, "oci-layout")); err != nil {
		t.Errorf("expected oci-layout file in output dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "index.json")); err != nil {
		t.Errorf("expected index.json in output dir: %v", err)
	}

	// Digest must be set.
	if result.Digest.Hex == "" {
		t.Error("expected non-empty image digest")
	}

	// ELF resolver must have added inferred-elf entries.
	var inferredCount int
	for _, e := range m.Files {
		if e.Source == manifest.SourceInferredELF {
			inferredCount++
		}
	}
	if inferredCount == 0 {
		t.Error("expected ELF resolver to add inferred-elf entries for nginx's shared libraries")
	}

	// No unresolved DT_NEEDED entries.
	if len(result.Unresolved) > 0 {
		t.Errorf("unexpected unresolved ELF deps: %v", result.Unresolved)
	}

	// FileCount must be positive.
	if result.FileCount == 0 {
		t.Error("expected non-zero FileCount")
	}

	// No missing includes (we didn't request any).
	if len(result.MissingIncludes) != 0 {
		t.Errorf("expected empty MissingIncludes, got %v", result.MissingIncludes)
	}

	t.Logf("BuildImage OK: %d files, %d inferred-elf, digest=%s",
		result.FileCount, inferredCount, result.Digest)
}

// TestBuildImage_NginxAlpine_IncludePaths verifies that --include adds
// directory-inclusion entries for files under the specified in-image path.
// nginx:1.25-alpine ships /usr/share/nginx/html/{index.html,50x.html}.
//
// Requires network access; skipped in short mode.
func TestBuildImage_NginxAlpine_IncludePaths(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	result, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform:     "linux/amd64",
			Keychain:     NewKeychain(),
			IncludePaths: []string{"/usr/share/nginx/html"},
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	// The include path exists in nginx, so MissingIncludes must be empty.
	if len(result.MissingIncludes) != 0 {
		t.Errorf("expected no missing includes for /usr/share/nginx/html, got %v", result.MissingIncludes)
	}

	// At least index.html and 50x.html should appear as directory-inclusion.
	var dirIncluded []string
	for path, e := range m.Files {
		if e.Source == manifest.SourceDirectoryInclusion {
			dirIncluded = append(dirIncluded, path)
		}
	}
	if len(dirIncluded) == 0 {
		t.Error("expected directory-inclusion entries after --include /usr/share/nginx/html")
	}
	t.Logf("directory-inclusion entries: %v", dirIncluded)

	// Verify IncludedBecause is set correctly.
	for _, path := range dirIncluded {
		e := m.Files[path]
		want := "directory-inclusion: --include /usr/share/nginx/html"
		if e.IncludedBecause != want {
			t.Errorf("%s: IncludedBecause = %q, want %q", path, e.IncludedBecause, want)
		}
	}

	// File count should be larger than without --include.
	t.Logf("FileCount with include: %d (added %d directory-inclusion entries)", result.FileCount, len(dirIncluded))
}

// TestBuildImage_NginxAlpine_MissingInclude verifies that a non-existent
// --include path is reported in MissingIncludes and does not cause an error.
//
// Requires network access; skipped in short mode.
func TestBuildImage_NginxAlpine_MissingInclude(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	result, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform:     "linux/amd64",
			Keychain:     NewKeychain(),
			IncludePaths: []string{"/nonexistent/test/path"},
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	// /nonexistent/test/path must appear in MissingIncludes.
	if len(result.MissingIncludes) != 1 || result.MissingIncludes[0] != "/nonexistent/test/path" {
		t.Errorf("expected MissingIncludes=[/nonexistent/test/path], got %v", result.MissingIncludes)
	}

	// Build must still succeed (non-fatal).
	if result.Digest.Hex == "" {
		t.Error("expected non-empty image digest despite missing include path")
	}

	// No directory-inclusion entries from the missing path.
	for path, e := range m.Files {
		if e.Source == manifest.SourceDirectoryInclusion {
			t.Errorf("unexpected directory-inclusion entry %s — path did not exist", path)
		}
	}
}

// TestBuildImage_NginxAlpine_ConfidenceScore exercises the confidence scorer
// against a manifest produced by the full BuildImage pipeline. A well-seeded
// manifest (15-minute window, only direct + inferred-elf + scratch-compat
// entries) should score High (≥80). This verifies that scratch-compat manual
// entries added by BuildImage do NOT penalise the confidence score.
//
// Requires network access; skipped in short mode.
func TestBuildImage_NginxAlpine_ConfidenceScore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest() // 15-minute window, 1 direct entry, no user manual entries

	if _, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform: "linux/amd64",
			Keychain: NewKeychain(),
		},
	); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	// Verify scratch-compat entries were added as manual by BuildImage.
	var scratchCount int
	for _, e := range m.Files {
		if e.Source == manifest.SourceManual && e.IncludedBecause == "scratch-compat" {
			scratchCount++
		}
	}
	if scratchCount == 0 {
		t.Error("expected scratch-compat manual entries from BuildImage")
	}

	// Compute confidence. Scratch-compat entries must NOT be penalised.
	// Profile window is 15m ≥ 10m min, no user manual entries → High (≥80).
	r := manifest.ComputeConfidence(m, manifest.DefaultMinProfileDuration)
	if r.Score < 80 {
		t.Errorf("expected High confidence (≥80) for 15-min profile with only scratch-compat manual entries; got %d (%s), penalties: %v",
			r.Score, r.Level, r.Penalties)
	}
	t.Logf("confidence: %d/100 (%s), orphan-inferred: %d (audit only)", r.Score, r.Level, len(r.OrphanInferred))
}

// ── EnsurePaths integration tests ─────────────────────────────────────────────

// TestBuildImage_EnsureDir_CreatesTypeDir verifies that a path declared via
// EnsurePaths with IsDir=true produces a tar.TypeDir entry in the OCI layer,
// even when the path does not exist in the source image.
//
// Requires network access; skipped in short mode.
func TestBuildImage_EnsureDir_CreatesTypeDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	const ensuredDir = "/var/cache/nginx/client_temp"
	result, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform: "linux/amd64",
			Keychain: NewKeychain(),
			EnsurePaths: []EnsureEntry{
				{Path: ensuredDir, IsDir: true},
			},
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if result.EnsuredCount != 1 {
		t.Errorf("want EnsuredCount=1, got %d", result.EnsuredCount)
	}

	// Inspect the OCI layer tar for a TypeDir entry at the expected path.
	layerTarPath := findLayerTar(t, outputDir)
	assertTarEntryType(t, layerTarPath, "var/cache/nginx/client_temp/", tar.TypeDir)
}

// TestBuildImage_EnsureFile_CreatesEmptyRegEntry verifies that a path declared
// via EnsurePaths with IsDir=false produces a 0-byte tar.TypeReg entry.
//
// Requires network access; skipped in short mode.
func TestBuildImage_EnsureFile_CreatesEmptyRegEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	const ensuredFile = "/run/nginx.pid"
	_, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform:    "linux/amd64",
			Keychain:    NewKeychain(),
			EnsurePaths: []EnsureEntry{{Path: ensuredFile, IsDir: false}},
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	layerTarPath := findLayerTar(t, outputDir)
	assertTarEntryType(t, layerTarPath, "run/nginx.pid", tar.TypeReg)
}

// TestBuildImage_EnsureDir_ParentDirsCreated verifies that intermediate parent
// directories are synthesised when using a deep EnsurePaths entry.
func TestBuildImage_EnsureDir_ParentDirsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()

	_, err := BuildImage(
		t.Context(),
		"nginx:1.25-alpine",
		m,
		outputDir,
		BuildOptions{
			Platform:    "linux/amd64",
			Keychain:    NewKeychain(),
			EnsurePaths: []EnsureEntry{{Path: "/a/b/c/d", IsDir: true}},
		},
	)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	layerTarPath := findLayerTar(t, outputDir)
	// Parent dirs must also be present.
	for _, p := range []string{"a/", "a/b/", "a/b/c/", "a/b/c/d/"} {
		assertTarEntryType(t, layerTarPath, p, tar.TypeDir)
	}
}

// findLayerTar locates the compressed layer blob in an OCI layout directory.
func findLayerTar(t *testing.T, outputDir string) string {
	t.Helper()
	indexData, err := os.ReadFile(filepath.Join(outputDir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var idx struct {
		Manifests []struct{ Digest string }
	}
	if err := json.Unmarshal(indexData, &idx); err != nil || len(idx.Manifests) == 0 {
		t.Fatalf("parse index.json: %v", err)
	}
	mfDigest := strings.TrimPrefix(idx.Manifests[0].Digest, "sha256:")
	mfData, err := os.ReadFile(filepath.Join(outputDir, "blobs", "sha256", mfDigest))
	if err != nil {
		t.Fatalf("read manifest blob: %v", err)
	}
	var mf struct {
		Layers []struct{ Digest string }
	}
	if err := json.Unmarshal(mfData, &mf); err != nil || len(mf.Layers) == 0 {
		t.Fatalf("parse manifest: %v", err)
	}
	layerDigest := strings.TrimPrefix(mf.Layers[0].Digest, "sha256:")
	return filepath.Join(outputDir, "blobs", "sha256", layerDigest)
}

// assertTarEntryType opens a gzip-compressed tar and asserts that entryName
// exists with the given Typeflag.
func assertTarEntryType(t *testing.T, layerPath, entryName string, wantType byte) {
	t.Helper()
	f, err := os.Open(layerPath)
	if err != nil {
		t.Fatalf("open layer: %v", err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if hdr.Name == entryName {
			if hdr.Typeflag != wantType {
				t.Errorf("entry %q: want Typeflag=%d, got %d", entryName, wantType, hdr.Typeflag)
			}
			return
		}
	}
	t.Errorf("entry %q not found in layer", entryName)
}
