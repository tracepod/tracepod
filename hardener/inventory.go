package hardener

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Inventory entry types.
const (
	InventoryTypeFile    = "file"
	InventoryTypeDir     = "dir"
	InventoryTypeSymlink = "symlink"
	InventoryTypeOther   = "other"
)

// InventoryFilename is the default file name of the inventory written next to
// the OCI layout by `harden build`.
const InventoryFilename = "inventory.json"

// InventoryVersion is the current value of InventoryFile.Version.
const InventoryVersion = 1

// InventoryEntry describes one path of the extracted source image filesystem.
type InventoryEntry struct {
	// Path is the absolute in-image path: "/"-rooted, no trailing slash.
	Path string `json:"path"`
	// Type is one of "file", "dir", "symlink" or "other" (device, fifo,
	// socket). Hardlinks are materialised as regular files during extraction
	// and are therefore reported as "file".
	Type string `json:"type"`
	// LinkTarget is the raw os.Readlink value (relative or absolute, never
	// resolved). Set for symlinks only.
	LinkTarget string `json:"link_target,omitempty"`
	// InHardened is true when the path is present in the hardened image layer.
	InHardened bool `json:"in_hardened"`
}

// InventoryFile is the on-disk document written by `harden build`.
type InventoryFile struct {
	Version        int              `json:"version"`
	SourceDigest   string           `json:"source_digest"`
	HardenedDigest string           `json:"hardened_digest"`
	Files          []InventoryEntry `json:"files"`
}

// collectInventory walks the extracted source tree rooted at stagingDir and
// returns one entry per path, sorted by Path. retained is the final set of
// hardened-image paths (keys of the manifest after the layer was built). A
// directory is in the hardened image when it is retained itself or is an
// ancestor of any retained path (the layer creates parent directories
// implicitly). Paths in retained that do not exist in stagingDir (ensure
// entries, fabricated scratch-compat files) are not listed. Symlinks are never
// followed.
func collectInventory(stagingDir string, retained map[string]struct{}) ([]InventoryEntry, error) {
	// Ancestor directory set, built once: O(n * depth).
	ancestors := make(map[string]struct{})
	for p := range retained {
		for d := parentPath(p); d != "/" && d != ""; d = parentPath(d) {
			if _, seen := ancestors[d]; seen {
				break // everything above is already recorded
			}
			ancestors[d] = struct{}{}
		}
	}

	entries := []InventoryEntry{}
	err := filepath.WalkDir(stagingDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stagingDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		path := "/" + filepath.ToSlash(rel)

		e := InventoryEntry{Path: path}
		switch t := d.Type(); {
		case t&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			e.Type = InventoryTypeSymlink
			e.LinkTarget = target
		case t.IsDir():
			e.Type = InventoryTypeDir
		case t.IsRegular():
			e.Type = InventoryTypeFile
		default:
			e.Type = InventoryTypeOther
		}

		_, e.InHardened = retained[path]
		if !e.InHardened && e.Type == InventoryTypeDir {
			_, e.InHardened = ancestors[path]
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", stagingDir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// parentPath returns the parent of an absolute slash-separated path
// ("/a/b" -> "/a", "/a" -> "/").
func parentPath(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// WriteInventory writes f as 2-space indented JSON to path, creating parent
// directories as needed.
func WriteInventory(path string, f InventoryFile) error {
	if f.Files == nil {
		f.Files = []InventoryEntry{}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create inventory dir: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write inventory: %w", err)
	}
	return nil
}
