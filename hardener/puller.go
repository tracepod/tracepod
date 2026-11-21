package hardener

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/tracepod/tracepod/manifest"
)

// PullOptions controls how the image is fetched.
type PullOptions struct {
	// Keychain resolves registry credentials. Use NewKeychain() or
	// NewExplicitKeychain() from keychain.go.
	Keychain authn.Keychain

	// Platform selects the image variant from a multi-arch manifest.
	// Format: "os/arch" e.g. "linux/amd64", "linux/arm64".
	// Defaults to "linux/amd64" when empty.
	Platform string

	// Insecure skips TLS certificate verification. Use only for on-prem
	// registries with self-signed certs. A warning is printed when set.
	Insecure bool
}

// ExtractFromImage pulls imageRef and extracts its complete filesystem into
// stagingDir (all layers, oldest-to-newest). The manifest is used only to
// identify ENOENT probes: manifest paths absent from all layers are returned
// in the missing slice as warnings — the sensor records every openat(2)
// attempt regardless of whether the kernel returned ENOENT.
//
// Whiteout semantics:
//   - .wh.<name>     — deletes the named sibling file from stagingDir.
//   - .wh..wh..opq   — opaque whiteout: clears the parent directory.
//
// Symlinks are written as symlinks (not dereferenced). The staging tree is
// readable and writable by the calling user whatever the source modes are:
// regular files get owner read+write (setuid, setgid and sticky are dropped),
// directories owner rwx, and device nodes and fifos are created as empty
// placeholder files. Extended attributes are not applied. This lets the
// hardener run without privileges; BuildImage takes the real metadata from the
// source layers' tar headers.
//
// After extraction, call ResolveELFDependencies(stagingDir, m) to find
// inferred-elf entries. Then call CopyFileSet(m, stagingDir, destDir) to
// materialise only the needed files.
func ExtractFromImage(
	ctx context.Context,
	imageRef string,
	m *manifest.Manifest,
	stagingDir string,
	opts PullOptions,
) (missing []string, err error) {
	if _, err := extractImage(ctx, imageRef, stagingDir, opts); err != nil {
		return nil, err
	}

	// Identify manifest paths absent from the staging (ENOENT probes).
	for path := range m.Files {
		if _, err := os.Lstat(filepath.Join(stagingDir, path)); err != nil {
			missing = append(missing, path)
		}
	}
	return missing, nil
}

// extractImage pulls imageRef, extracts every layer into stagingDir and
// returns the source metadata of every extracted path (see stagingMeta).
func extractImage(ctx context.Context, imageRef, stagingDir string, opts PullOptions) (stagingMeta, error) {
	if opts.Platform == "" {
		opts.Platform = "linux/amd64"
	}
	if opts.Insecure {
		fmt.Fprintf(os.Stderr, "warning: --insecure set; TLS certificate verification disabled\n")
	}

	plat, err := parsePlatform(opts.Platform)
	if err != nil {
		return nil, fmt.Errorf("parse platform %q: %w", opts.Platform, err)
	}

	craneOpts := []crane.Option{
		crane.WithContext(ctx),
		crane.WithPlatform(plat),
	}
	if opts.Keychain != nil {
		craneOpts = append(craneOpts, crane.WithAuthFromKeychain(opts.Keychain))
	}
	if opts.Insecure {
		craneOpts = append(craneOpts, crane.Insecure)
	}

	img, err := crane.Pull(imageRef, craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", imageRef, err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	// Extract ALL files (nil wanted = extract everything).
	meta := stagingMeta{}
	for _, layer := range layers {
		if err := extractLayer(layer, stagingDir, nil, meta); err != nil {
			return nil, err
		}
	}
	return meta, nil
}

// CopyFileSet copies every file listed in m.Files from srcDir into destDir,
// preserving directory structure and permissions. Symlinks are re-created as
// symlinks. Files absent from srcDir are silently skipped (they were already
// reported as missing by ExtractFromImage).
func CopyFileSet(m *manifest.Manifest, srcDir, destDir string) error {
	for path := range m.Files {
		src := filepath.Join(srcDir, path)
		dst := filepath.Join(destDir, path)

		info, err := os.Lstat(src)
		if os.IsNotExist(err) {
			continue // ENOENT probe — not present in image
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", src, err)
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
		}

		if info.IsDir() {
			if err := os.MkdirAll(dst, info.Mode()); err != nil {
				return fmt.Errorf("mkdir %s: %w", dst, err)
			}
			continue
		}

		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", src, err)
			}
			_ = os.Remove(dst)
			if err := os.Symlink(target, dst); err != nil {
				return fmt.Errorf("symlink %s: %w", dst, err)
			}
			continue
		}

		in, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open %s: %w", src, err)
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			in.Close()
			return fmt.Errorf("create %s: %w", dst, err)
		}
		_, copyErr := io.Copy(out, in)
		in.Close()
		out.Close()
		if copyErr != nil {
			return fmt.Errorf("copy %s: %w", dst, copyErr)
		}
	}
	return nil
}

// extractLayer iterates a single layer's tar and extracts or applies whiteouts.
// wanted is updated in place: paths found are set to true. When meta is
// non-nil it records the header metadata of every extracted path and drops
// whited-out paths.
func extractLayer(layer v1.Layer, destDir string, wanted map[string]bool, meta stagingMeta) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("open layer: %w", err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // PAX global header: not a filesystem entry
		}

		// Normalise: OCI tars may omit the leading slash.
		name := hdr.Name
		if !strings.HasPrefix(name, "/") {
			name = "/" + name
		}
		// Strip trailing slash from directory entries.
		name = strings.TrimSuffix(name, "/")
		key := path.Clean(name)

		dir := filepath.Dir(name)
		base := filepath.Base(name)

		// --- whiteout handling ---
		if strings.HasPrefix(base, ".wh.") {
			if base == ".wh..wh..opq" {
				// Opaque whiteout: remove all existing contents of this directory.
				destParent := filepath.Join(destDir, dir)
				if err := removeDirectoryContents(destParent); err != nil {
					fmt.Fprintf(os.Stderr, "warning: opaque whiteout on %s: %v\n", dir, err)
				}
				meta.forget(path.Clean(dir), true)
			} else {
				// Named whiteout: remove the specific file.
				deleted := filepath.Join(dir, strings.TrimPrefix(base, ".wh."))
				if _, inManifest := wanted[deleted]; inManifest {
					fmt.Fprintf(os.Stderr, "warning: manifest file %s was whited-out in image layer\n", deleted)
					wanted[deleted] = true // mark found so we don't error later
				}
				destPath := filepath.Join(destDir, deleted)
				// A whited-out directory goes with everything beneath it.
				_ = os.RemoveAll(destPath)
				meta.forget(path.Clean(deleted), true)
			}
			continue
		}

		// If wanted is non-nil, only extract files listed in it.
		if wanted != nil {
			if _, ok := wanted[name]; !ok {
				continue
			}
		}

		destPath := filepath.Join(destDir, name)
		parentDir := filepath.Dir(destPath)
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", parentDir, err)
		}
		// Staged directories always keep owner rwx (see stagedDirMode), even
		// when a layer sets a restrictive mode such as 000 (eclipse-temurin
		// does that to /usr/bin in an intermediate layer), so entries can
		// always be created inside them without privileges.

		sm := metaFromHeader(hdr)
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			// Remove existing symlink/file first (layer override).
			_ = os.Remove(destPath)
			if err := os.Symlink(hdr.Linkname, destPath); err != nil {
				return fmt.Errorf("symlink %s → %s: %w", destPath, hdr.Linkname, err)
			}

		case tar.TypeLink:
			target := filepath.Join(destDir, "/"+hdr.Linkname)
			_ = os.Remove(destPath)
			if err := os.Link(target, destPath); err != nil {
				return fmt.Errorf("hardlink %s → %s: %w", destPath, target, err)
			}
			// A hard link shares its target's inode, hence its metadata.
			if tm, ok := meta[path.Clean("/"+hdr.Linkname)]; ok {
				cp := *tm
				sm = &cp
			}

		case tar.TypeDir:
			mode := stagedDirMode(hdr.Mode)
			if err := os.MkdirAll(destPath, mode); err != nil {
				return fmt.Errorf("mkdir %s: %w", destPath, err)
			}
			// MkdirAll leaves an existing directory alone and applies the
			// umask to a new one: set the staged mode explicitly.
			if err := os.Chmod(destPath, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", destPath, err)
			}

		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			// Creating device nodes needs privileges and opening a fifo
			// blocks. Stage an empty placeholder; the layer writer emits the
			// real entry from the header metadata.
			_ = os.RemoveAll(destPath)
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, stagedFileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create %s: %w", destPath, err)
			}
			f.Close()

		default:
			// Remove any existing entry at destPath before writing. A later
			// layer may change a symlink to a regular file (or vice versa);
			// if we don't remove first, os.OpenFile() follows the symlink and
			// tries to write to whatever it points to (possibly a host binary).
			// Also handles the case where a prior layer wrote the same file
			// with restrictive permissions (000, execute-only) that would deny
			// O_WRONLY — removing and recreating is simpler than chmod+retry.
			// The staged copy always has owner read+write so the hardener can
			// read it without privileges (stagedFileMode).
			_ = os.Remove(destPath)
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, stagedFileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create %s: %w", destPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", destPath, err)
			}
			f.Close()
		}

		if meta != nil {
			if hdr.Typeflag != tar.TypeDir {
				// A non-directory replaces anything that was at this path.
				meta.forget(key, true)
			}
			meta[key] = sm
		}
		if wanted != nil {
			wanted[name] = true
		}
	}
	return nil
}

// removeDirectoryContents removes the entries inside dir without removing dir
// itself.
func removeDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// parsePlatform converts "linux/amd64" → v1.Platform.
func parsePlatform(s string) (*v1.Platform, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected os/arch, got %q", s)
	}
	return &v1.Platform{OS: parts[0], Architecture: parts[1]}, nil
}
