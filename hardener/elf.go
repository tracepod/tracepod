package hardener

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// ResolveELFDependencies walks every file currently in m that lives under
// extractedDir, identifies ELF binaries by magic bytes, and recursively
// resolves all DT_NEEDED shared-library dependencies.
//
// Newly discovered libraries are added to m with source "inferred-elf".
// Returns the list of paths (relative to extractedDir) that were added.
//
// If a DT_NEEDED entry cannot be resolved, it is collected and returned as
// unresolved — the caller decides whether to treat that as fatal (the CLI
// exits 1 when len(unresolved) > 0).
//
// Known limitations (cannot be solved statically):
//   - dlopen(): runtime dynamic loading is not visible in ELF metadata.
//   - LD_LIBRARY_PATH from the container's runtime environment is treated as
//     unset. Directory inclusion via --include is the recommended mitigation
//     for both cases.
func ResolveELFDependencies(
	extractedDir string,
	m *manifest.Manifest,
) (added []string, unresolved []string, err error) {
	ldPaths, err := parseLdSoConf(extractedDir)
	if err != nil {
		// Non-fatal: fall back to standard paths only.
		fmt.Fprintf(os.Stderr, "warning: ld.so.conf parse error: %v; using standard paths\n", err)
	}

	// Canonicalise the root once: resolved library paths come from
	// filepath.EvalSymlinks and must share a prefix with root, otherwise a
	// root reached through a symlink (e.g. macOS /var -> /private/var) yields
	// host-absolute paths that are mistaken for in-image paths.
	if real, rErr := filepath.EvalSymlinks(extractedDir); rErr == nil {
		extractedDir = real
	}

	resolver := &elfResolver{
		root:     extractedDir,
		ldPaths:  append(ldPaths, standardLibPaths...),
		visited:  make(map[string]struct{}),
		manifest: m,
	}

	// Seed: all ELF files already in the manifest.
	seeds := make([]string, 0, len(m.Files))
	for p := range m.Files {
		seeds = append(seeds, p)
	}

	for _, p := range seeds {
		// Follow links (including directory links such as merged-usr /bin)
		// inside the image root, so a seed that is a symlink to an ELF
		// binary has its dependencies resolved too.
		real, rerr := resolveInRoot(extractedDir, p, maxSymlinkHops)
		if rerr != nil || !isELF(filepath.Join(extractedDir, real)) {
			continue
		}
		a, u, err := resolver.resolve(real, p)
		if err != nil {
			return nil, nil, err
		}
		added = append(added, a...)
		unresolved = append(unresolved, u...)
	}
	return added, unresolved, nil
}

// standardLibPaths are checked after RPATH/RUNPATH and ld.so.conf.
// Both x86_64 and aarch64 multilib paths are included so the resolver works
// for manifests captured from either architecture.
var standardLibPaths = []string{
	"/lib",
	"/usr/lib",
	"/lib/x86_64-linux-gnu",
	"/usr/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu",
	"/usr/lib/aarch64-linux-gnu",
	"/lib64",
	"/usr/lib64",
}

type elfResolver struct {
	root     string
	ldPaths  []string
	visited  map[string]struct{} // canonical in-image paths already resolved (cycle prevention)
	manifest *manifest.Manifest
}

// resolve resolves all DT_NEEDED entries for the ELF binary at realPath, a
// canonical in-image path (no symlinks, as returned by resolveInRoot).
// manifestPath is the absolute-in-image path used as the InferredFrom label.
func (r *elfResolver) resolve(realPath, manifestPath string) (added, unresolved []string, err error) {
	if _, seen := r.visited[realPath]; seen {
		return nil, nil, nil
	}
	r.visited[realPath] = struct{}{}

	absPath := filepath.Join(r.root, filepath.FromSlash(realPath))
	f, err := elf.Open(absPath)
	if err != nil {
		// Not a valid ELF (e.g. script, data file) — silently skip.
		return nil, nil, nil
	}
	defer f.Close()

	needed, err := f.ImportedLibraries()
	if err != nil {
		return nil, nil, fmt.Errorf("read DT_NEEDED from %s: %w", absPath, err)
	}

	// PT_INTERP: the dynamic linker/interpreter. The kernel loads this
	// directly during execve() — it never appears in openat() traces —
	// so we must include it explicitly when a binary is in the manifest.
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			buf := make([]byte, prog.Filesz)
			if _, rerr := prog.ReadAt(buf, 0); rerr == nil {
				interpPath := strings.TrimRight(string(buf), "\x00")
				if interpPath != "" {
					interpReal, ierr := resolveInRoot(r.root, interpPath, maxSymlinkHops)
					if ierr == nil {
						if _, exists := r.manifest.Files[interpPath]; !exists {
							r.manifest.Files[interpPath] = manifest.FileEntry{
								Source:       manifest.SourceInferredELF,
								AccessModes:  []manifest.AccessMode{},
								FirstSeen:    time.Now().UTC(),
								LastSeen:     time.Now().UTC(),
								Count:        0,
								InferredFrom: manifestPath,
							}
							added = append(added, interpPath)
						}
						// Recurse: the interpreter is itself an ELF that may have deps.
						a, u, rerr := r.resolve(interpReal, interpPath)
						if rerr == nil {
							added = append(added, a...)
							unresolved = append(unresolved, u...)
						}
					}
				}
			}
			break // only one PT_INTERP per binary
		}
	}

	// Build search path list for this binary: RPATH / RUNPATH → ldPaths.
	searchPaths, err := r.buildSearchPaths(f, realPath)
	if err != nil {
		return nil, nil, err
	}

	for _, lib := range needed {
		resolvedReal, resolvedManifest, err := r.findLib(lib, searchPaths)
		if err != nil {
			// Could not find the library — record as unresolved, continue.
			unresolved = append(unresolved, lib)
			continue
		}

		// If already in manifest (direct or previously inferred), skip adding
		// but still recurse to catch its own DT_NEEDED if not yet visited.
		if _, exists := r.manifest.Files[resolvedManifest]; !exists {
			r.manifest.Files[resolvedManifest] = manifest.FileEntry{
				Source:       manifest.SourceInferredELF,
				AccessModes:  []manifest.AccessMode{},
				FirstSeen:    time.Now().UTC(),
				LastSeen:     time.Now().UTC(),
				Count:        0,
				InferredFrom: manifestPath,
			}
			added = append(added, resolvedManifest)
		}

		// Recurse into the resolved library.
		a, u, err := r.resolve(resolvedReal, resolvedManifest)
		if err != nil {
			return nil, nil, err
		}
		added = append(added, a...)
		unresolved = append(unresolved, u...)

		// If the library was reached via a symlink (or a directory symlink),
		// also include its real in-image location (e.g. libssl.so.3 behind
		// libssl.so).
		if resolvedReal != resolvedManifest {
			if _, exists := r.manifest.Files[resolvedReal]; !exists {
				r.manifest.Files[resolvedReal] = manifest.FileEntry{
					Source:       manifest.SourceInferredELF,
					AccessModes:  []manifest.AccessMode{},
					FirstSeen:    time.Now().UTC(),
					LastSeen:     time.Now().UTC(),
					Count:        0,
					InferredFrom: manifestPath,
				}
				added = append(added, resolvedReal)
			}
		}
	}
	return added, unresolved, nil
}

// buildSearchPaths constructs the ordered library search path for an ELF
// binary following the Linux dynamic linker rules:
//
//  1. DT_RPATH  — only if DT_RUNPATH is absent (presence of DT_RUNPATH
//     cancels DT_RPATH inheritance per the ELF spec).
//  2. DT_RUNPATH.
//  3. ldPaths   — from ld.so.conf + standard paths.
//
// $ORIGIN is substituted with the in-image directory of the ELF binary; binPath
// is a canonical in-image path.
func (r *elfResolver) buildSearchPaths(f *elf.File, binPath string) ([]string, error) {
	binDir := path.Dir(binPath) // in-image directory, so $ORIGIN stays inside the root

	runpaths, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		runpaths = nil
	}
	rpaths, err := f.DynString(elf.DT_RPATH)
	if err != nil {
		rpaths = nil
	}

	var order []string

	if len(runpaths) > 0 {
		// DT_RUNPATH present — use it, ignore DT_RPATH.
		for _, rp := range runpaths {
			for _, p := range filepath.SplitList(rp) {
				order = append(order, r.resolveOrigin(p, binDir))
			}
		}
	} else if len(rpaths) > 0 {
		// DT_RPATH present, DT_RUNPATH absent — use DT_RPATH.
		for _, rp := range rpaths {
			for _, p := range filepath.SplitList(rp) {
				order = append(order, r.resolveOrigin(p, binDir))
			}
		}
	}

	order = append(order, r.ldPaths...)
	return order, nil
}

// resolveOrigin substitutes $ORIGIN (and ${ORIGIN}) in a path token with
// originDir (the directory of the ELF binary being processed).
func (r *elfResolver) resolveOrigin(token, originDir string) string {
	token = strings.ReplaceAll(token, "${ORIGIN}", originDir)
	token = strings.ReplaceAll(token, "$ORIGIN", originDir)
	return token
}

// findLib searches for libName in the given ordered search paths (all paths
// are in-image paths, resolved inside r.root). It returns the canonical
// in-image path of the library with all symlinks followed (realPath) and the
// absolute in-image path as found along the search path (manifestPath).
// A candidate that is dangling or part of a symlink loop is skipped, as the
// dynamic linker would skip it.
func (r *elfResolver) findLib(libName string, searchPaths []string) (realPath, manifestPath string, err error) {
	for _, dir := range searchPaths {
		manifestPath = path.Join("/", filepath.ToSlash(dir), libName)
		// Resolve the uncleaned path: lexically cleaning ".." before following
		// directory symlinks would differ from what the dynamic linker does.
		real, rerr := resolveInRoot(r.root, "/"+filepath.ToSlash(dir)+"/"+libName, maxSymlinkHops)
		if rerr != nil {
			continue
		}
		return real, manifestPath, nil
	}
	return "", "", fmt.Errorf("library %q not found in search paths", libName)
}

// isELF reports whether the file at path begins with the ELF magic bytes.
// It uses Lstat (no symlink follow) to skip non-regular files: symlinks,
// directories, FIFOs, and character devices are never ELF binaries, and
// opening FIFOs can block indefinitely waiting for a writer.
func isELF(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// parseLdSoConf parses /etc/ld.so.conf (and all included files) within root,
// returning the list of library search directories in order.
func parseLdSoConf(root string) ([]string, error) {
	return parseLdSoConfFile(root, "/etc/ld.so.conf", make(map[string]struct{}))
}

func parseLdSoConfFile(root, confPath string, seen map[string]struct{}) ([]string, error) {
	if _, visited := seen[confPath]; visited {
		return nil, nil // circular include guard
	}
	seen[confPath] = struct{}{}

	hostPath := filepath.Join(root, confPath)
	f, err := os.Open(hostPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var dirs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "include ") {
			pattern := strings.TrimSpace(strings.TrimPrefix(line, "include "))
			// pattern is relative to the image root.
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(confPath), pattern)
			}
			matches, err := filepath.Glob(filepath.Join(root, pattern))
			if err != nil {
				continue
			}
			for _, match := range matches {
				// Convert host match back to an image-relative path.
				rel, err := filepath.Rel(root, match)
				if err != nil {
					continue
				}
				sub, err := parseLdSoConfFile(root, "/"+rel, seen)
				if err != nil {
					continue
				}
				dirs = append(dirs, sub...)
			}
			continue
		}
		dirs = append(dirs, line)
	}
	return dirs, scanner.Err()
}
