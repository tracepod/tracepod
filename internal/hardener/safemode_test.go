package hardener

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tracepod/tracepod/internal/manifest"
)

// makeTestManifest returns an empty manifest ready for safemode tests.
func makeTestManifest() *manifest.Manifest {
	now := time.Now()
	return &manifest.Manifest{
		SchemaVersion: "1",
		ContainerID:   "test",
		ProfileStart:  now,
		ProfileEnd:    now,
		Files:         map[string]manifest.FileEntry{},
	}
}

// writeFile creates a file with the given contents under dir.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestApplyDirectoryInclusion_Basic verifies that regular files are added to the manifest.
func TestApplyDirectoryInclusion_Basic(t *testing.T) {
	stagingDir := t.TempDir()
	// Create /usr/share/nginx/html/ with 3 files.
	htmlDir := filepath.Join(stagingDir, "usr", "share", "nginx", "html")
	if err := os.MkdirAll(htmlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, htmlDir, "index.html", "<html/>")
	writeFile(t, htmlDir, "50x.html", "<html/>")
	writeFile(t, htmlDir, "favicon.ico", "icon")

	m := makeTestManifest()
	added, missing, err := ApplyDirectoryInclusion(stagingDir, []string{"/usr/share/nginx/html"}, m)
	if err != nil {
		t.Fatalf("ApplyDirectoryInclusion: %v", err)
	}
	if added != 3 {
		t.Errorf("expected 3 added, got %d", added)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing paths, got %v", missing)
	}
	for _, name := range []string{"index.html", "50x.html", "favicon.ico"} {
		imagePath := "/usr/share/nginx/html/" + name
		e, ok := m.Files[imagePath]
		if !ok {
			t.Errorf("expected %s in manifest", imagePath)
			continue
		}
		if e.Source != manifest.SourceDirectoryInclusion {
			t.Errorf("%s: expected SourceDirectoryInclusion, got %s", imagePath, e.Source)
		}
		if e.IncludedBecause != "directory-inclusion: --include /usr/share/nginx/html" {
			t.Errorf("%s: unexpected IncludedBecause %q", imagePath, e.IncludedBecause)
		}
	}
}

// TestApplyDirectoryInclusion_SkipsExistingEntries verifies existing manifest
// entries are not overwritten.
func TestApplyDirectoryInclusion_SkipsExistingEntries(t *testing.T) {
	stagingDir := t.TempDir()
	htmlDir := filepath.Join(stagingDir, "usr", "share", "nginx", "html")
	if err := os.MkdirAll(htmlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, htmlDir, "index.html", "<html/>")
	writeFile(t, htmlDir, "other.html", "<html/>")

	m := makeTestManifest()
	// Pre-seed index.html as a direct entry.
	m.Files["/usr/share/nginx/html/index.html"] = manifest.FileEntry{
		Source: manifest.SourceDirect,
		Count:  5,
	}

	added, _, err := ApplyDirectoryInclusion(stagingDir, []string{"/usr/share/nginx/html"}, m)
	if err != nil {
		t.Fatal(err)
	}
	// Only other.html should be added; index.html is already present.
	if added != 1 {
		t.Errorf("expected 1 added (not overwriting existing), got %d", added)
	}
	// Direct entry must be preserved.
	e := m.Files["/usr/share/nginx/html/index.html"]
	if e.Source != manifest.SourceDirect || e.Count != 5 {
		t.Errorf("existing direct entry was overwritten: %+v", e)
	}
}

// TestApplyDirectoryInclusion_IncludesSymlinks verifies file symlinks are added and
// directory symlinks are included as entries but not descended into.
func TestApplyDirectoryInclusion_IncludesSymlinks(t *testing.T) {
	stagingDir := t.TempDir()
	dir := filepath.Join(stagingDir, "etc", "nginx")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "nginx.conf", "server {}")
	// File symlink — should be included.
	fileSymlink := filepath.Join(dir, "nginx.conf.link")
	if err := os.Symlink(filepath.Join(dir, "nginx.conf"), fileSymlink); err != nil {
		t.Fatal(err)
	}
	// Directory symlink — should be included as an entry but not descended into.
	dirSymlink := filepath.Join(dir, "conf.d.link")
	if err := os.Symlink(dir, dirSymlink); err != nil {
		t.Fatal(err)
	}

	m := makeTestManifest()
	added, _, err := ApplyDirectoryInclusion(stagingDir, []string{"/etc/nginx"}, m)
	if err != nil {
		t.Fatal(err)
	}
	// nginx.conf (regular) + nginx.conf.link (file symlink) + conf.d.link (dir symlink) = 3.
	if added != 3 {
		t.Errorf("expected 3 added (1 regular + 2 symlinks), got %d", added)
	}
	if _, ok := m.Files["/etc/nginx/nginx.conf.link"]; !ok {
		t.Error("file symlink should be in manifest")
	}
	if _, ok := m.Files["/etc/nginx/conf.d.link"]; !ok {
		t.Error("directory symlink should be in manifest as a single entry")
	}
}

// TestApplyDirectoryInclusion_SkipsSubdirEntries verifies directory entries are not added.
func TestApplyDirectoryInclusion_SkipsSubdirEntries(t *testing.T) {
	stagingDir := t.TempDir()
	parent := filepath.Join(stagingDir, "app")
	sub := filepath.Join(parent, "subdir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, parent, "main.conf", "conf")
	writeFile(t, sub, "sub.conf", "sub")

	m := makeTestManifest()
	added, _, err := ApplyDirectoryInclusion(stagingDir, []string{"/app"}, m)
	if err != nil {
		t.Fatal(err)
	}
	// Both files (in parent and subdir) should be added; the directory itself should not.
	if added != 2 {
		t.Errorf("expected 2 added (2 regular files, no dir entries), got %d", added)
	}
	// Directory entry /app/subdir must not be in manifest as a FileEntry.
	if e, ok := m.Files["/app/subdir"]; ok {
		t.Errorf("directory /app/subdir should not be in manifest as a file entry: %+v", e)
	}
}

// TestApplyDirectoryInclusion_NonExistentPath verifies that a missing includePath
// is collected in the missing return value and does not cause an error.
func TestApplyDirectoryInclusion_NonExistentPath(t *testing.T) {
	stagingDir := t.TempDir()
	m := makeTestManifest()

	added, missing, err := ApplyDirectoryInclusion(stagingDir, []string{"/var/log/nginx"}, m)
	if err != nil {
		t.Fatalf("expected no error for non-existent path, got: %v", err)
	}
	if added != 0 {
		t.Errorf("expected 0 added, got %d", added)
	}
	if len(missing) != 1 || missing[0] != "/var/log/nginx" {
		t.Errorf("expected missing=[/var/log/nginx], got %v", missing)
	}
}

// TestApplyDirectoryInclusion_MultiplePaths verifies entries from multiple
// includePaths are all added, with non-existent ones collected in missing.
func TestApplyDirectoryInclusion_MultiplePaths(t *testing.T) {
	stagingDir := t.TempDir()

	htmlDir := filepath.Join(stagingDir, "usr", "share", "nginx", "html")
	if err := os.MkdirAll(htmlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, htmlDir, "index.html", "<html/>")

	pluginsDir := filepath.Join(stagingDir, "etc", "nginx", "modules")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pluginsDir, "mod_http.so", "ELF")
	writeFile(t, pluginsDir, "mod_stream.so", "ELF")

	m := makeTestManifest()
	added, missing, err := ApplyDirectoryInclusion(stagingDir, []string{
		"/usr/share/nginx/html",
		"/etc/nginx/modules",
		"/var/log/nginx", // does not exist
	}, m)
	if err != nil {
		t.Fatalf("ApplyDirectoryInclusion: %v", err)
	}
	if added != 3 {
		t.Errorf("expected 3 added (1 html + 2 modules), got %d", added)
	}
	if len(missing) != 1 || missing[0] != "/var/log/nginx" {
		t.Errorf("expected missing=[/var/log/nginx], got %v", missing)
	}
}

// TestApplyDirectoryInclusion_IncludedBecauseField verifies the IncludedBecause
// field is set correctly for the given includePath.
func TestApplyDirectoryInclusion_IncludedBecauseField(t *testing.T) {
	stagingDir := t.TempDir()
	dir := filepath.Join(stagingDir, "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "file.txt", "data")

	m := makeTestManifest()
	_, _, err := ApplyDirectoryInclusion(stagingDir, []string{"/data"}, m)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m.Files["/data/file.txt"]
	if !ok {
		t.Fatal("expected /data/file.txt in manifest")
	}
	want := "directory-inclusion: --include /data"
	if e.IncludedBecause != want {
		t.Errorf("IncludedBecause = %q, want %q", e.IncludedBecause, want)
	}
}

// ── ApplyEnsurePaths tests ────────────────────────────────────────────────────

func TestApplyEnsurePaths_Directory(t *testing.T) {
	m := makeTestManifest()
	ApplyEnsurePaths([]EnsureEntry{{Path: "/var/cache/nginx/client_temp", IsDir: true}}, m)

	e, ok := m.Files["/var/cache/nginx/client_temp"]
	if !ok {
		t.Fatal("expected entry for /var/cache/nginx/client_temp")
	}
	if e.Source != manifest.SourceEnsureDir {
		t.Errorf("want source=%s, got %s", manifest.SourceEnsureDir, e.Source)
	}
	if e.Count != 0 {
		t.Errorf("want count=0, got %d", e.Count)
	}
}

func TestApplyEnsurePaths_File(t *testing.T) {
	m := makeTestManifest()
	ApplyEnsurePaths([]EnsureEntry{{Path: "/run/nginx.pid", IsDir: false}}, m)

	e, ok := m.Files["/run/nginx.pid"]
	if !ok {
		t.Fatal("expected entry for /run/nginx.pid")
	}
	if e.Source != manifest.SourceEnsureFile {
		t.Errorf("want source=%s, got %s", manifest.SourceEnsureFile, e.Source)
	}
}

func TestApplyEnsurePaths_DoesNotOverwriteHigherPriority(t *testing.T) {
	m := makeTestManifest()
	// Pre-seed with a direct entry.
	m.Files["/etc/nginx/nginx.conf"] = manifest.FileEntry{
		Source: manifest.SourceDirect,
		Count:  10,
	}
	ApplyEnsurePaths([]EnsureEntry{{Path: "/etc/nginx/nginx.conf", IsDir: false}}, m)

	if m.Files["/etc/nginx/nginx.conf"].Source != manifest.SourceDirect {
		t.Error("ApplyEnsurePaths must not overwrite a direct entry")
	}
	if m.Files["/etc/nginx/nginx.conf"].Count != 10 {
		t.Error("Count should be unchanged")
	}
}

func TestApplyEnsurePaths_EmptyInput(t *testing.T) {
	m := makeTestManifest()
	m.Files["/usr/sbin/nginx"] = manifest.FileEntry{Source: manifest.SourceDirect}
	ApplyEnsurePaths(nil, m)
	if len(m.Files) != 1 {
		t.Errorf("want 1 entry unchanged, got %d", len(m.Files))
	}
}

func TestApplyEnsurePaths_AuditTrail(t *testing.T) {
	m := makeTestManifest()
	ApplyEnsurePaths([]EnsureEntry{
		{Path: "/var/cache/nginx", IsDir: true},
		{Path: "/run/nginx.pid", IsDir: false},
	}, m)

	dir := m.Files["/var/cache/nginx"]
	if dir.IncludedBecause != "ensure-dir: --mkdir /var/cache/nginx" {
		t.Errorf("unexpected IncludedBecause for dir: %q", dir.IncludedBecause)
	}
	file := m.Files["/run/nginx.pid"]
	if file.IncludedBecause != "ensure-file: --touch /run/nginx.pid" {
		t.Errorf("unexpected IncludedBecause for file: %q", file.IncludedBecause)
	}
}
