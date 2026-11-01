package hardener

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxSymlinkHops mirrors the Linux kernel's limit on symlinks followed while
// resolving one path (MAXSYMLINKS).
const maxSymlinkHops = 40

// errTooManyLinks is returned by resolveInRoot for symlink loops and chains
// longer than the hop limit.
var errTooManyLinks = errors.New("too many levels of symbolic links")

// resolveInRoot resolves inImagePath chroot-style inside root and returns the
// canonical absolute in-image path with every symlink (including the final
// component) followed. It never consults the host's filesystem outside root:
//
//   - an absolute link target is re-rooted at root;
//   - a relative link target is taken relative to the directory that holds the
//     link, after that directory has itself been resolved;
//   - ".." never climbs above root (as in a real chroot);
//   - at most maxHops links are followed, otherwise errTooManyLinks.
//
// A missing component (including a dangling link) yields an error wrapping
// os.ErrNotExist. root must itself be free of symlinks (canonicalise it once
// with filepath.EvalSymlinks); components below it are examined one by one
// with Lstat, so no host symlink resolution ever applies to them.
func resolveInRoot(root, inImagePath string, maxHops int) (string, error) {
	var cur []string // resolved in-image components, no symlinks among them
	pending := splitPath(inImagePath)
	hops := 0

	for len(pending) > 0 {
		comp := pending[0]
		pending = pending[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}

		next := append(append([]string(nil), cur...), comp)
		fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash("/"+strings.Join(next, "/"))))
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}

		hops++
		if hops > maxHops {
			return "", fmt.Errorf("resolve %s: %w", inImagePath, errTooManyLinks)
		}
		target, err := os.Readlink(filepath.Join(root, filepath.FromSlash("/"+strings.Join(next, "/"))))
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") {
			cur = nil // absolute: restart at the image root
		}
		// Relative: cur is unchanged, i.e. the directory holding the link.
		pending = append(splitPath(target), pending...)
	}
	return "/" + strings.Join(cur, "/"), nil
}

func splitPath(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}

// inRootHostPath returns the host path of inImagePath with every directory
// component resolved inside root but the final component left as-is (so the
// result can be passed to os.Lstat / os.Readlink to inspect a symlink itself).
// If the parent directory cannot be resolved it falls back to a plain join,
// which makes the caller's os call report the underlying error.
func inRootHostPath(root, inImagePath string) string {
	clean := path.Clean("/" + filepath.ToSlash(inImagePath))
	if clean == "/" {
		return root
	}
	dir, base := path.Split(clean)
	realDir, err := resolveInRoot(root, dir, maxSymlinkHops)
	if err != nil {
		return filepath.Join(root, filepath.FromSlash(clean))
	}
	return filepath.Join(root, filepath.FromSlash(realDir), base)
}
