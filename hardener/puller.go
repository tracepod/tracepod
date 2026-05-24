package hardener

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
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
// Symlinks are written as symlinks (not dereferenced).
// File permissions from the tar header are preserved.
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
	for _, layer := range layers {
		if err := extractLayer(layer, stagingDir, nil); err != nil {
			return nil, err
		}
	}

	// Identify manifest paths absent from the staging (ENOENT probes).
	for path := range m.Files {
		if _, err := os.Lstat(filepath.Join(stagingDir, path)); err != nil {
			missing = append(missing, path)
		}
	}
	return missing, nil
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
// wanted is updated in place: paths found are set to true.
func extractLayer(layer v1.Layer, destDir string, wanted map[string]bool) error {
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

		// Normalise: OCI tars may omit the leading slash.
		name := hdr.Name
		if !strings.HasPrefix(name, "/") {
			name = "/" + name
		}
		// Strip trailing slash from directory entries.
		name = strings.TrimSuffix(name, "/")

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
			} else {
				// Named whiteout: remove the specific file.
				deleted := filepath.Join(dir, strings.TrimPrefix(base, ".wh."))
				if _, inManifest := wanted[deleted]; inManifest {
					fmt.Fprintf(os.Stderr, "warning: manifest file %s was whited-out in image layer\n", deleted)
					wanted[deleted] = true // mark found so we don't error later
				}
				destPath := filepath.Join(destDir, deleted)
				_ = os.Remove(destPath)
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
		// A previous layer may have set the parent directory to mode 000 (e.g.
		// eclipse-temurin sets /usr/bin to 000 in an intermediate layer). Ensure
		// the parent is always traversable so we can create entries inside it.
		_ = os.Chmod(parentDir, 0o755)

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

		case tar.TypeDir:
			if err := os.MkdirAll(destPath, hdr.FileInfo().Mode()); err != nil {
				return fmt.Errorf("mkdir %s: %w", destPath, err)
			}

		default:
			// Remove any existing entry at destPath before writing. A later
			// layer may change a symlink to a regular file (or vice versa);
			// if we don't remove first, os.OpenFile() follows the symlink and
			// tries to write to whatever it points to (possibly a host binary).
			// Also handles the case where a prior layer wrote the same file
			// with restrictive permissions (000, execute-only) that would deny
			// O_WRONLY — removing and recreating is simpler than chmod+retry.
			_ = os.Remove(destPath)
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("create %s: %w", destPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", destPath, err)
			}
			f.Close()
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
