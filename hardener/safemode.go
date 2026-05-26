// Package hardener — safemode.go implements directory-inclusion.
// ApplyDirectoryInclusion walks caller-specified directories in the staging
// area and adds every regular file found to the manifest with
// SourceDirectoryInclusion. This is the primary escape hatch for paths the
// eBPF sensor cannot observe: static web content, known dlopen plugin
// directories, and directories created at runtime that must be pre-seeded.
package hardener

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// ApplyDirectoryInclusion walks each path in includePaths within stagingDir,
// adding every regular file and file symlink found to m with SourceDirectoryInclusion.
// includePaths are absolute-in-image paths (e.g. "/usr/share/nginx/html").
//
// Behaviour:
//   - Regular files and file symlinks are included. Directory symlinks are not
//     descended into (WalkDir does not follow them), but are included as entries.
//   - Plain directories, FIFOs and other non-regular, non-symlink entries are skipped.
//   - Paths already present in m are not overwritten — direct and inferred-elf
//     entries take precedence.
//   - If an includePath does not exist in stagingDir, it is collected in the
//     returned missing slice (not treated as an error). The caller should emit
//     a Warning: line for each missing path.
//
// Returns the count of newly added manifest entries, the list of includePaths
// not found in stagingDir, and any fatal walk error.
func ApplyDirectoryInclusion(stagingDir string, includePaths []string, m *manifest.Manifest) (added int, missing []string, err error) {
	now := time.Now().UTC()

	for _, inclPath := range includePaths {
		// Strip the leading slash so filepath.Join produces a valid host path.
		rel := strings.TrimPrefix(inclPath, "/")
		absDir := filepath.Join(stagingDir, rel)

		// Check existence before walking so we can collect missing paths.
		if _, statErr := os.Lstat(absDir); os.IsNotExist(statErr) {
			missing = append(missing, inclPath)
			continue
		}

		walkErr := filepath.WalkDir(absDir, func(absPath string, d fs.DirEntry, walkEntryErr error) error {
			if walkEntryErr != nil {
				// Skip unreadable entries; don't abort the walk.
				return nil
			}
			// Include regular files and file symlinks. WalkDir reports symlinks
			// as DirEntry items with ModeSymlink set but does not descend into
			// directory symlinks. Directories, FIFOs, and other special files
			// are skipped. The builder (writeTarEntries) handles symlinks
			// correctly via os.Lstat + tar.TypeSymlink.
			if !d.Type().IsRegular() && d.Type()&fs.ModeSymlink == 0 {
				return nil
			}

			// Compute the absolute-in-image path.
			relPath, relErr := filepath.Rel(stagingDir, absPath)
			if relErr != nil {
				return nil
			}
			imagePath := "/" + relPath

			// Existing entries (direct, inferred-elf, etc.) take precedence.
			if _, exists := m.Files[imagePath]; exists {
				return nil
			}

			m.Files[imagePath] = manifest.FileEntry{
				Source:          manifest.SourceDirectoryInclusion,
				FirstSeen:       now,
				LastSeen:        now,
				Count:           0,
				IncludedBecause: "directory-inclusion: --include " + inclPath,
			}
			added++
			return nil
		})

		if walkErr != nil {
			return added, missing, walkErr
		}
	}

	return added, missing, nil
}

// EnsureEntry declares a path that must exist in the hardened OCI image.
type EnsureEntry struct {
	// Path is the absolute-in-image path, e.g. "/var/cache/nginx/client_temp".
	Path string
	// IsDir when true creates a tar.TypeDir entry; false creates a 0-byte tar.TypeReg entry.
	IsDir bool
}

// ApplyEnsurePaths adds manifest entries for each EnsureEntry so that
// writeTarEntries will write the corresponding OCI layer entries.
//
// For directories (IsDir=true): adds a SourceEnsureDir marker unconditionally,
// whether or not the path exists in stagingDir. The directory will appear in
// the output layer regardless of source image content.
//
// For files (IsDir=false): adds a SourceEnsureFile marker only if the path is
// not already present in m. If the real file is present in the staged source it
// will have been added during the manifest collection phase and takes precedence.
//
// Existing entries with higher-priority sources (direct, inferred-elf, etc.) are
// never overwritten. Parent directories are synthesised by writeTarEntries.
func ApplyEnsurePaths(entries []EnsureEntry, m *manifest.Manifest) {
	now := time.Now().UTC()
	for _, e := range entries {
		if _, exists := m.Files[e.Path]; exists {
			continue
		}
		src := manifest.SourceEnsureDir
		because := "ensure-dir: --mkdir " + e.Path
		if !e.IsDir {
			src = manifest.SourceEnsureFile
			because = "ensure-file: --touch " + e.Path
		}
		m.Files[e.Path] = manifest.FileEntry{
			Source:          src,
			FirstSeen:       now,
			LastSeen:        now,
			Count:           0,
			IncludedBecause: because,
		}
	}
}
