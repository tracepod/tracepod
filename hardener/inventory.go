package hardener

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
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
//
// Version history:
//   - 1: one entry per source-image path; in_hardened says whether that exact
//     path is in the hardened layer. Paths that exist only in the hardened
//     layer are not listed, and the hardened type of a path is not recorded.
//   - 2: the inventory describes both trees. Every path of the source tree and
//     every path of the hardened layer is listed once; in_source,
//     hardened_type and hardened_link_target were added, and in_hardened is
//     true whenever the path exists in the hardened layer, whatever its type
//     there (a source symlink such as /lib -> usr/lib that the layer holds as a
//     real directory is in_hardened with hardened_type "dir").
const InventoryVersion = 2

// InventoryEntry describes one path of the source image filesystem, of the
// hardened image layer, or of both.
type InventoryEntry struct {
	// Path is the absolute in-image path: "/"-rooted, no trailing slash.
	Path string `json:"path"`
	// Type is the path's type in the source tree: one of "file", "dir",
	// "symlink" or "other" (device, fifo, socket). Hardlinks are materialised
	// as regular files during extraction and are therefore reported as "file".
	// Empty when the path is not in the source tree (InSource is false).
	Type string `json:"type,omitempty"`
	// LinkTarget is the raw os.Readlink value in the source tree (relative or
	// absolute, never resolved). Set for source symlinks only.
	LinkTarget string `json:"link_target,omitempty"`
	// InHardened is true when the path is present in the hardened image layer
	// (with any type; see HardenedType).
	InHardened bool `json:"in_hardened"`
	// InSource is true when the path is present in the source tree. Version 1
	// documents only list source paths; ReadInventory / DecodeInventory set it
	// for them.
	InSource bool `json:"in_source"`
	// HardenedType is the path's type in the hardened layer ("file", "dir",
	// "symlink" or "other"); empty when the path is not in the hardened layer
	// or the document predates version 2. It can differ from Type: the layer
	// materialises parent directories of every kept path as real directories,
	// so a source symlink to a directory can become a directory.
	HardenedType string `json:"hardened_type,omitempty"`
	// HardenedLinkTarget is the raw link value of a hardened-layer symlink.
	HardenedLinkTarget string `json:"hardened_link_target,omitempty"`
}

// InventoryFile is the on-disk document written by `harden build`.
type InventoryFile struct {
	Version        int              `json:"version"`
	SourceDigest   string           `json:"source_digest"`
	HardenedDigest string           `json:"hardened_digest"`
	Files          []InventoryEntry `json:"files"`
}

// DescribesHardenedTree reports whether f lists the hardened layer's own
// paths and types (version 2 and later). For older documents only the
// source-tree fields and InHardened are meaningful.
func (f InventoryFile) DescribesHardenedTree() bool { return f.Version >= 2 }

// layerNode is one path of a layer, after the layer's entries are applied.
type layerNode struct {
	Type       string
	LinkTarget string
}

// layerTree maps an absolute in-image path to its node.
type layerTree map[string]layerNode

// readLayerTree applies the tar stream r to an empty tree the way a container
// runtime extracts a layer onto an empty root and returns the result:
//
//   - entries are applied in stream order and a later entry for the same path
//     replaces an earlier one, except that a directory entry over an existing
//     directory leaves it (and its contents) in place;
//   - replacing a directory with a non-directory removes everything below it;
//   - missing parent directories are created implicitly; a parent that is
//     currently a non-directory is replaced by a directory (the hardened layer
//     always writes parent directories explicitly, so this only covers
//     hand-written streams).
//
// Whiteout entries (".wh.") are not expected in a single-layer image built
// from scratch and are recorded like any other file. Hardlinks are reported
// as "file".
func readLayerTree(r io.Reader) (layerTree, error) {
	tree := layerTree{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return tree, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read layer: %w", err)
		}
		p := path.Clean("/" + strings.TrimPrefix(hdr.Name, "./"))
		if p == "/" {
			continue
		}
		n := layerNode{}
		switch hdr.Typeflag {
		case tar.TypeDir:
			n.Type = InventoryTypeDir
		case tar.TypeSymlink:
			n.Type = InventoryTypeSymlink
			n.LinkTarget = hdr.Linkname
		case tar.TypeReg, tar.TypeLink:
			n.Type = InventoryTypeFile
		default:
			n.Type = InventoryTypeOther
		}
		tree.ensureParents(p)
		tree.put(p, n)
	}
}

// put records n at p with layer-application semantics (see readLayerTree).
func (t layerTree) put(p string, n layerNode) {
	old, exists := t[p]
	if exists && old.Type == InventoryTypeDir {
		if n.Type == InventoryTypeDir {
			return
		}
		t.removeBelow(p)
	}
	t[p] = n
}

// ensureParents creates p's missing ancestors as directories.
func (t layerTree) ensureParents(p string) {
	for d := parentPath(p); d != "/"; d = parentPath(d) {
		if n, ok := t[d]; ok && n.Type == InventoryTypeDir {
			return // everything above already exists as directories
		}
		t.put(d, layerNode{Type: InventoryTypeDir})
	}
}

// removeBelow deletes every path strictly below directory p.
func (t layerTree) removeBelow(p string) {
	prefix := p + "/"
	for k := range t {
		if strings.HasPrefix(k, prefix) {
			delete(t, k)
		}
	}
}

// inventoryForLayer reads the hardened tree from the built layer itself (so
// the inventory describes exactly what a runtime extracts) and merges it with
// the extracted source tree in stagingDir.
func inventoryForLayer(stagingDir string, layer v1.Layer) ([]InventoryEntry, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("open hardened layer: %w", err)
	}
	defer rc.Close()
	tree, err := readLayerTree(rc)
	if err != nil {
		return nil, err
	}
	return collectInventory(stagingDir, tree)
}

// collectInventory walks the extracted source tree rooted at stagingDir and
// merges it with hardened, the hardened layer's tree (see readLayerTree). It
// returns one entry per path present in either tree, sorted by Path. Source
// symlinks are never followed: a path is listed under the name it has in each
// tree, so a file reached through a symlinked source directory (/lib ->
// usr/lib) appears under its source name (/usr/lib/x) and, when the hardened
// layer holds it under the accessed name, as a hardened-only entry (/lib/x).
func collectInventory(stagingDir string, hardened layerTree) ([]InventoryEntry, error) {
	entries := []InventoryEntry{}
	seen := make(map[string]struct{}, len(hardened))
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

		e := InventoryEntry{Path: path, InSource: true}
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
		if n, ok := hardened[path]; ok {
			e.InHardened = true
			e.HardenedType = n.Type
			e.HardenedLinkTarget = n.LinkTarget
			seen[path] = struct{}{}
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", stagingDir, err)
	}
	for p, n := range hardened {
		if _, ok := seen[p]; ok {
			continue
		}
		entries = append(entries, InventoryEntry{
			Path:               p,
			InHardened:         true,
			HardenedType:       n.Type,
			HardenedLinkTarget: n.LinkTarget,
		})
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

// ReadInventory reads and decodes the inventory document at path (see
// DecodeInventory).
func ReadInventory(path string) (InventoryFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return InventoryFile{}, fmt.Errorf("read inventory: %w", err)
	}
	return DecodeInventory(bytes.NewReader(data))
}

// DecodeInventory decodes an inventory document of any supported version
// (1..InventoryVersion). Version 1 entries are normalised to the current
// field set: every entry gets InSource = true (version 1 lists only source
// paths); HardenedType stays empty because version 1 does not record it, so
// callers that need the hardened tree must check DescribesHardenedTree.
func DecodeInventory(r io.Reader) (InventoryFile, error) {
	var f InventoryFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return InventoryFile{}, fmt.Errorf("decode inventory: %w", err)
	}
	if f.Version < 1 || f.Version > InventoryVersion {
		return InventoryFile{}, fmt.Errorf("unsupported inventory version %d (supported: 1..%d)", f.Version, InventoryVersion)
	}
	if f.Version == 1 {
		for i := range f.Files {
			f.Files[i].InSource = true
		}
	}
	if f.Files == nil {
		f.Files = []InventoryEntry{}
	}
	return f, nil
}
