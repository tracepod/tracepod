// Package hardener — builder.go assembles a FROM-scratch OCI image from the
// files collected during profiling.
package hardener

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/tracepod/tracepod/manifest"
)

// BuildOptions controls how the minimal OCI image is assembled and published.
type BuildOptions struct {
	// Platform selects the image variant. Format: "os/arch", e.g. "linux/amd64".
	// Defaults to "linux/amd64".
	Platform string

	// Keychain resolves registry credentials. Use NewKeychain() or
	// NewExplicitKeychain() from keychain.go.
	Keychain authn.Keychain

	// Insecure skips TLS certificate verification.
	Insecure bool

	// WorkDir is the parent directory for the staging area.
	// If empty, os.TempDir() is used.
	WorkDir string

	// PushRef is the full image reference to push to after building,
	// e.g. "123456789.dkr.ecr.eu-west-1.amazonaws.com/myapp:hardened".
	// Empty = skip push.
	PushRef string

	// IncludePaths are absolute-in-image directory paths to force-include via
	// directory-inclusion. Every regular file found under each path in the
	// extracted staging directory is added to the manifest with
	// SourceDirectoryInclusion. Applied after ELF resolution, before layer
	// construction. Corresponds to the --include CLI flag.
	IncludePaths []string

	// EnsurePaths are paths that must exist in the output OCI layer regardless
	// of whether they exist in the source image. Directories write a tar.TypeDir
	// entry; files write an empty tar.TypeReg entry (0 bytes). Applied after
	// IncludePaths. Corresponds to --mkdir / --touch CLI flags.
	EnsurePaths []EnsureEntry
}

// BuildResult summarises the image that was produced.
type BuildResult struct {
	// Digest is the OCI image manifest digest (sha256:...).
	Digest v1.Hash

	// LayerDigest is the compressed layer digest.
	LayerDigest v1.Hash

	// LayerSize is the compressed layer size in bytes.
	LayerSize int64

	// FileCount is the total number of files in the image (manifest + inferred-elf + scratch-compat).
	FileCount int

	// ScratchWarnings lists paths that were absent from the source image layers.
	// These are non-fatal but may affect runtime behaviour.
	ScratchWarnings []string

	// Unresolved lists DT_NEEDED library names that the ELF resolver could not locate.
	Unresolved []string

	// MissingIncludes lists --include paths not found in the source image staging
	// directory. Non-fatal; the caller should emit a Warning: line for each.
	MissingIncludes []string

	// EnsuredCount is the number of ensure-dir + ensure-file entries added to the layer.
	EnsuredCount int

	// SourceDigest is the digest of the pulled source image.
	SourceDigest v1.Hash

	// SourceSize is the compressed size of all source image layers in bytes.
	SourceSize int64

	// Pushed is true if the image was pushed to PushRef.
	Pushed bool

	// PushedRef is the registry reference the image was pushed to.
	PushedRef string
}

// scratchEssentials are files that must be present for a FROM-scratch image to
// function correctly. They are copied from the source image layers if present;
// a warning is emitted for each that is absent.
var scratchEssentials = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/nsswitch.conf",
	// /etc/ssl/certs handled separately (directory fallback).
	// /etc/resolv.conf handled separately (bind-mounted at runtime; warn-only).
}

// dynamicLinkers lists the expected dynamic linker paths per architecture.
// The ELF resolver catches DT_NEEDED entries but NOT the PT_INTERP dynamic
// linker (loaded directly by the kernel), so we check for it explicitly.
// Both glibc and musl paths are listed — Alpine uses musl, Debian/Ubuntu use glibc.
var dynamicLinkers = map[string][]string{
	"amd64": {
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", // glibc (Debian/Ubuntu)
		"/lib64/ld-linux-x86-64.so.2",                 // glibc (RHEL/Fedora)
		"/lib/ld-musl-x86_64.so.1",                    // musl (Alpine)
	},
	"arm64": {
		"/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", // glibc (Debian/Ubuntu)
		"/lib/ld-linux-aarch64.so.1",                   // glibc (RHEL/Fedora)
		"/lib/ld-musl-aarch64.so.1",                    // musl (Alpine)
	},
}

// BuildImage pulls sourceRef, extracts the files listed in m, resolves ELF
// shared-library dependencies, injects scratch-compatibility essentials,
// assembles a FROM-scratch OCI image, and writes it as an OCI layout to
// outputDir. If opts.PushRef is non-empty the image is also pushed there.
//
// The manifest m is mutated in place: ELF-inferred entries and scratch-compat
// entries are added.
func BuildImage(
	ctx context.Context,
	sourceRef string,
	m *manifest.Manifest,
	outputDir string,
	opts BuildOptions,
) (BuildResult, error) {
	if opts.Platform == "" {
		opts.Platform = "linux/amd64"
	}

	craneOpts := buildCraneOptions(ctx, opts)

	// Pull source image to get its config and digest. crane.Pull is lazy:
	// this downloads only the manifest JSON and config blob, not layer blobs.
	sourceImg, err := crane.Pull(sourceRef, craneOpts...)
	if err != nil {
		return BuildResult{}, fmt.Errorf("pull %s: %w", sourceRef, err)
	}
	sourceCfgFile, err := sourceImg.ConfigFile()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get source config: %w", err)
	}
	sourceDigest, err := sourceImg.Digest()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get source digest: %w", err)
	}
	// Compute source size from manifest layer sizes (already fetched by crane.Pull).
	// sourceImg.Size() only returns the manifest JSON size for remote images,
	// not the actual layer content — sum the layer sizes from the manifest directly.
	sourceSize := int64(0)
	if srcManifest, mErr := sourceImg.Manifest(); mErr == nil {
		for _, l := range srcManifest.Layers {
			sourceSize += l.Size
		}
	}

	// Create staging directory for full image extraction.
	stagingDir, err := os.MkdirTemp(opts.WorkDir, "tracepod-staging-*")
	if err != nil {
		return BuildResult{}, fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	// Extract the complete image filesystem (all layers). ExtractFromImage
	// re-pulls the image internally; only the layer blobs are downloaded again
	// (the manifest + config were already fetched above).
	pullOpts := PullOptions{
		Keychain: opts.Keychain,
		Platform: opts.Platform,
		Insecure: opts.Insecure,
	}
	_, err = ExtractFromImage(ctx, sourceRef, m, stagingDir, pullOpts)
	if err != nil {
		return BuildResult{}, fmt.Errorf("extract image: %w", err)
	}

	// Resolve ELF shared-library dependencies against the full staging tree.
	_, unresolved, err := ResolveELFDependencies(stagingDir, m)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve ELF deps: %w", err)
	}

	// Inject scratch-compatibility essentials: /etc/passwd, TLS certs,
	// dynamic linker, etc. These are pulled from the extracted staging tree.
	arch := archFromPlatform(opts.Platform)
	scratchWarnings := checkScratchCompat(m, stagingDir, arch)

	// Apply directory inclusion for any --include paths. This runs after
	// ELF resolution and scratch-compat injection so that directory-included
	// files respect the same precedence order: direct > inferred-elf > manual >
	// directory-inclusion.
	var missingIncludes []string
	if len(opts.IncludePaths) > 0 {
		_, missingIncludes, err = ApplyDirectoryInclusion(stagingDir, opts.IncludePaths, m)
		if err != nil {
			return BuildResult{}, fmt.Errorf("apply directory inclusion: %w", err)
		}
	}

	// Apply ensure-dir / ensure-file entries (--mkdir / --touch).
	// These run after directory-inclusion so that source-image files take precedence.
	var ensuredCount int
	if len(opts.EnsurePaths) > 0 {
		before := len(m.Files)
		ApplyEnsurePaths(opts.EnsurePaths, m)
		ensuredCount = len(m.Files) - before
	}

	// Build a deterministic, gzip-compressed tar layer from the final file set.
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return buildLayer(m, stagingDir)
	})
	if err != nil {
		return BuildResult{}, fmt.Errorf("create OCI layer: %w", err)
	}

	// Assemble the image: start from empty (FROM scratch), append one layer.
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return BuildResult{}, fmt.Errorf("append layer: %w", err)
	}

	// Get the post-append config (has correct RootFS DiffIDs), then overlay
	// runtime metadata from the source image.
	baseCfgFile, err := img.ConfigFile()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get base config: %w", err)
	}
	newCfgFile := buildConfigFile(baseCfgFile, sourceCfgFile, m, sourceRef, sourceDigest.String())
	img, err = mutate.ConfigFile(img, newCfgFile)
	if err != nil {
		return BuildResult{}, fmt.Errorf("set config: %w", err)
	}

	// Write OCI layout to outputDir.
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return BuildResult{}, fmt.Errorf("create output dir: %w", err)
	}
	lp, err := layout.Write(outputDir, empty.Index)
	if err != nil {
		return BuildResult{}, fmt.Errorf("create OCI layout: %w", err)
	}
	// Add org.opencontainers.image.ref.name so that "ctr images import --base-name"
	// and similar tools can resolve the image reference from the layout index.
	// Use PushRef when set; otherwise use a default name.
	layoutRef := opts.PushRef
	if layoutRef == "" {
		layoutRef = "localhost/tracepod:hardened"
	}
	if err := lp.AppendImage(img, layout.WithAnnotations(map[string]string{
		"org.opencontainers.image.ref.name": layoutRef,
	})); err != nil {
		return BuildResult{}, fmt.Errorf("write image to layout: %w", err)
	}

	// Collect result metadata.
	digest, err := img.Digest()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get image digest: %w", err)
	}
	layerDigest, err := layer.Digest()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get layer digest: %w", err)
	}
	layerSize, err := layer.Size()
	if err != nil {
		return BuildResult{}, fmt.Errorf("get layer size: %w", err)
	}

	result := BuildResult{
		Digest:          digest,
		LayerDigest:     layerDigest,
		LayerSize:       layerSize,
		FileCount:       len(m.Files),
		ScratchWarnings: scratchWarnings,
		Unresolved:      unresolved,
		MissingIncludes: missingIncludes,
		EnsuredCount:    ensuredCount,
		SourceDigest:    sourceDigest,
		SourceSize:      sourceSize,
	}

	// Push if requested.
	if opts.PushRef != "" {
		if err := crane.Push(img, opts.PushRef, craneOpts...); err != nil {
			return result, fmt.Errorf("push to %s: %w", opts.PushRef, err)
		}
		result.Pushed = true
		result.PushedRef = opts.PushRef
	}

	return result, nil
}

// buildConfigFile constructs the OCI ConfigFile for the minimised image.
//
// baseCfgFile comes from the image after AppendLayers and carries the correct
// RootFS DiffIDs. sourceCfgFile comes from the original image and carries the
// runtime config (Entrypoint, Cmd, Env, etc.). The two are merged: RootFS is
// taken from base, everything else from source, with tracepod provenance labels
// added and OnBuild/History stripped.
func buildConfigFile(
	baseCfgFile *v1.ConfigFile,
	sourceCfgFile *v1.ConfigFile,
	m *manifest.Manifest,
	sourceRef string,
	sourceDigest string,
) *v1.ConfigFile {
	out := *baseCfgFile // copy — preserves RootFS DiffIDs from AppendLayers

	// Adopt OS/arch from source so the image can be pulled on the right platform.
	out.OS = sourceCfgFile.OS
	out.Architecture = sourceCfgFile.Architecture
	out.OSVersion = sourceCfgFile.OSVersion
	out.OSFeatures = sourceCfgFile.OSFeatures
	out.Variant = sourceCfgFile.Variant
	out.Created = v1.Time{Time: time.Now().UTC()}

	// Adopt the full runtime config from the source image.
	out.Config = sourceCfgFile.Config

	// OnBuild is a build-time directive; meaningless in a pre-built image.
	out.Config.OnBuild = nil

	// Merge original labels with tracepod provenance (tracepod labels win on conflict).
	out.Config.Labels = mergeLabels(sourceCfgFile.Config.Labels, tracepodLabels(m, sourceRef, sourceDigest))

	// Strip build history; replace with a single provenance entry.
	out.History = []v1.History{
		{
			Created:   v1.Time{Time: time.Now().UTC()},
			CreatedBy: "tracepod hardener",
			Comment:   fmt.Sprintf("source=%s digest=%s files=%d", sourceRef, sourceDigest, len(m.Files)),
		},
	}

	return &out
}

// tracepodLabels returns the set of provenance labels added to every minimised image.
func tracepodLabels(m *manifest.Manifest, sourceRef, sourceDigest string) map[string]string {
	return map[string]string{
		"com.tracepod.source-image":  sourceRef,
		"com.tracepod.source-digest": sourceDigest,
		"com.tracepod.manifest-hash": manifestHash(m),
		"com.tracepod.profile-start": m.ProfileStart.UTC().Format(time.RFC3339),
		"com.tracepod.profile-end":   m.ProfileEnd.UTC().Format(time.RFC3339),
		"com.tracepod.build-time":    time.Now().UTC().Format(time.RFC3339),
	}
}

// manifestHash returns a stable sha256 hex digest of the manifest's file map.
func manifestHash(m *manifest.Manifest) string {
	data, err := json.Marshal(m.Files)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mergeLabels merges src and overlay; overlay values take precedence.
func mergeLabels(src, overlay map[string]string) map[string]string {
	if len(src) == 0 && len(overlay) == 0 {
		return nil
	}
	out := make(map[string]string, len(src)+len(overlay))
	for k, v := range src {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// checkScratchCompat checks for files required to run from a scratch base image.
// Files present in stagingDir are added to m with source=manual. Absent files
// produce a warning string. The function is non-fatal: the caller decides which
// warnings are errors based on context.
func checkScratchCompat(m *manifest.Manifest, stagingDir, arch string) []string {
	var warnings []string
	now := time.Now().UTC()

	// Core runtime files.
	for _, path := range scratchEssentials {
		if _, err := os.Lstat(filepath.Join(stagingDir, path)); err == nil {
			addScratchCompatEntry(m, path, now)
		} else {
			warnings = append(warnings, fmt.Sprintf("%s not found in image layers", path))
		}
	}

	// /etc/resolv.conf is typically bind-mounted by the container runtime at
	// startup, so its absence from image layers is expected and non-fatal.
	const resolvConf = "/etc/resolv.conf"
	if _, err := os.Lstat(filepath.Join(stagingDir, resolvConf)); err == nil {
		addScratchCompatEntry(m, resolvConf, now)
	} else {
		warnings = append(warnings, resolvConf+" not found in image layers (bind-mounted at runtime \u2014 OK)")
	}

	// CA certificate bundle, with directory fallback when the bundle is absent.
	const certBundle = "/etc/ssl/certs/ca-certificates.crt"
	const certDir = "/etc/ssl/certs"
	if _, err := os.Lstat(filepath.Join(stagingDir, certBundle)); err == nil {
		addScratchCompatEntry(m, certBundle, now)
	} else {
		dirEntries, dirErr := os.ReadDir(filepath.Join(stagingDir, certDir))
		if dirErr == nil && len(dirEntries) > 0 {
			for _, e := range dirEntries {
				p := certDir + "/" + e.Name()
				addScratchCompatEntry(m, p, now)
			}
		} else {
			warnings = append(warnings, certBundle+" not found in image layers (outbound TLS may fail)")
		}
	}

	// Dynamic linker — arch-specific. The ELF resolver typically catches this
	// via DT_NEEDED, but we verify explicitly since a missing linker is a silent
	// runtime failure.
	linkers := dynamicLinkers[arch]
	found := false
	for _, path := range linkers {
		if _, err := os.Lstat(filepath.Join(stagingDir, path)); err == nil {
			addScratchCompatEntry(m, path, now)
			found = true
			break
		}
	}
	if !found && len(linkers) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"dynamic linker not found for %s (checked: %s)", arch, strings.Join(linkers, ", "),
		))
	}

	return warnings
}

// addScratchCompatEntry adds path to m.Files with source=manual if not already present.
// Existing entries (direct observation or inferred-elf) take precedence.
func addScratchCompatEntry(m *manifest.Manifest, path string, t time.Time) {
	if _, ok := m.Files[path]; ok {
		return
	}
	m.Files[path] = manifest.FileEntry{
		Source:          manifest.SourceManual,
		AccessModes:     []manifest.AccessMode{manifest.AccessRead},
		FirstSeen:       t,
		LastSeen:        t,
		Count:           0,
		IncludedBecause: "scratch-compat",
	}
}

// buildLayer produces a gzip-compressed, deterministic tar ReadCloser containing
// all files in m.Files that exist in stagingDir. Paths are sorted for
// reproducibility; modification times are zeroed. Parent directories are
// synthesised as needed.
//
// tarball.LayerFromOpener calls this opener multiple times (once per digest
// computation, once when writing), so the output must be identical on every call.
func buildLayer(m *manifest.Manifest, stagingDir string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		gw := gzip.NewWriter(pw)
		tw := tar.NewWriter(gw)
		err := writeTarEntries(tw, m, stagingDir)
		tw.Close()
		gw.Close()
		pw.CloseWithError(err)
	}()
	return pr, nil
}

// expandSymlinkTargets adds the resolved absolute target of every symlink in
// m.Files to m.Files when the target exists in stagingDir but is not already
// in the manifest.  Relative targets are resolved against the symlink's parent
// directory.  Broken symlinks (target absent from stagingDir) are silently
// skipped.  The loop repeats until no new entries are added so that symlink
// chains (libfoo.so → libfoo.so.1 → libfoo.so.1.2.3) are fully expanded.
//
// This prevents dangling symlinks in the output OCI layer when the sensor only
// observed the symlink name (e.g. python, libz.so.1) and not its target.
func expandSymlinkTargets(m *manifest.Manifest, stagingDir string) {
	now := time.Now().UTC()
	for {
		added := 0
		for path := range m.Files {
			src := filepath.Join(stagingDir, path)
			info, err := os.Lstat(src)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := os.Readlink(src)
			if err != nil {
				continue
			}
			absTarget := target
			if !filepath.IsAbs(target) {
				absTarget = filepath.Join(filepath.Dir(path), target)
			}
			absTarget = filepath.Clean(absTarget)
			if _, ok := m.Files[absTarget]; ok {
				continue
			}
			if _, err := os.Lstat(filepath.Join(stagingDir, absTarget)); err != nil {
				continue // target absent from staging dir — broken symlink, skip
			}
			m.Files[absTarget] = manifest.FileEntry{
				Source:          manifest.SourceManual,
				FirstSeen:       now,
				LastSeen:        now,
				IncludedBecause: "symlink-target",
			}
			added++
		}
		if added == 0 {
			break
		}
	}
}

// writeTarEntries writes manifest entries into tw in sorted path order.
// Parent directories are synthesised before each entry. mtime is zeroed.
func writeTarEntries(tw *tar.Writer, m *manifest.Manifest, stagingDir string) error {
	// Expand symlink targets before building the sorted path list so that
	// symlinks pointing to targets absent from the manifest (e.g. python→python3,
	// libz.so.1→libz.so.1.3.1) produce a non-dangling layer.
	expandSymlinkTargets(m, stagingDir)

	paths := make([]string, 0, len(m.Files))
	for p := range m.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	emittedDirs := make(map[string]struct{})
	zeroTime := time.Time{}

	for _, path := range paths {
		if err := ensureParentDirs(tw, path, emittedDirs, zeroTime); err != nil {
			return err
		}

		entry := m.Files[path]
		src := filepath.Join(stagingDir, path)
		info, err := os.Lstat(src)
		if os.IsNotExist(err) {
			tarPath := strings.TrimPrefix(path, "/")
			switch entry.Source {
			case manifest.SourceEnsureDir:
				if _, seen := emittedDirs[path]; !seen {
					if err := tw.WriteHeader(&tar.Header{
						Typeflag: tar.TypeDir,
						Name:     tarPath + "/",
						Mode:     0o755,
						ModTime:  zeroTime,
					}); err != nil {
						return fmt.Errorf("tar ensure-dir %s: %w", path, err)
					}
					emittedDirs[path] = struct{}{}
				}
			case manifest.SourceEnsureFile:
				if err := tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeReg,
					Name:     tarPath,
					Size:     0,
					Mode:     0o644,
					ModTime:  zeroTime,
				}); err != nil {
					return fmt.Errorf("tar ensure-file %s: %w", path, err)
				}
			}
			continue // ENOENT probe or scratch-compat file absent from this image
		}
		if err != nil {
			// ENOTDIR means a path component is a file, not a directory
			// (e.g. kernel recorded "foo.php/.htaccess" from an Apache htaccess
			// probe that can never succeed). Treat it the same as ENOENT.
			if isNotDirErr(err) {
				continue
			}
			return fmt.Errorf("stat %s: %w", src, err)
		}

		// OCI tar convention: no leading slash on entry names.
		tarPath := strings.TrimPrefix(path, "/")

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(src)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", src, err)
			}
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeSymlink,
				Name:     tarPath,
				Linkname: target,
				ModTime:  zeroTime,
			}); err != nil {
				return fmt.Errorf("tar symlink header %s: %w", path, err)
			}

		case info.IsDir():
			if _, seen := emittedDirs[path]; !seen {
				if err := tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeDir,
					Name:     tarPath + "/",
					Mode:     int64(info.Mode().Perm()),
					ModTime:  zeroTime,
				}); err != nil {
					return fmt.Errorf("tar dir header %s: %w", path, err)
				}
				emittedDirs[path] = struct{}{}
			}

		default:
			f, err := os.Open(src)
			if err != nil {
				return fmt.Errorf("open %s: %w", src, err)
			}
			err = tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeReg,
				Name:     tarPath,
				Size:     info.Size(),
				Mode:     int64(info.Mode().Perm()),
				ModTime:  zeroTime,
			})
			if err != nil {
				f.Close()
				return fmt.Errorf("tar file header %s: %w", path, err)
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return fmt.Errorf("tar file body %s: %w", path, err)
			}
			f.Close()
		}
	}
	return nil
}

// ensureParentDirs emits tar directory entries for every ancestor of path
// that has not already been emitted.
func ensureParentDirs(tw *tar.Writer, path string, emitted map[string]struct{}, zeroTime time.Time) error {
	clean := strings.TrimPrefix(path, "/")
	parts := strings.Split(clean, "/")
	// Synthesise all ancestors except the final path component.
	for i := 1; i < len(parts); i++ {
		dir := "/" + strings.Join(parts[:i], "/")
		if _, seen := emitted[dir]; seen {
			continue
		}
		tarDir := strings.Join(parts[:i], "/") + "/"
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     tarDir,
			Mode:     0o755,
			ModTime:  zeroTime,
		}); err != nil {
			return fmt.Errorf("tar parent dir %s: %w", tarDir, err)
		}
		emitted[dir] = struct{}{}
	}
	return nil
}

// archFromPlatform returns the architecture component of a "os/arch" string.
func archFromPlatform(platform string) string {
	if i := strings.Index(platform, "/"); i >= 0 {
		return platform[i+1:]
	}
	return "amd64"
}

// buildCraneOptions constructs the crane.Option slice from BuildOptions.
func buildCraneOptions(ctx context.Context, opts BuildOptions) []crane.Option {
	out := []crane.Option{crane.WithContext(ctx)}
	if opts.Platform != "" {
		parts := strings.SplitN(opts.Platform, "/", 2)
		if len(parts) == 2 {
			out = append(out, crane.WithPlatform(&v1.Platform{
				OS:           parts[0],
				Architecture: parts[1],
			}))
		}
	}
	if opts.Keychain != nil {
		out = append(out, crane.WithAuthFromKeychain(opts.Keychain))
	}
	if opts.Insecure {
		out = append(out, crane.Insecure)
	}
	return out
}

// isNotDirErr returns true when err indicates that a path component that was
// expected to be a directory is actually a file (ENOTDIR).  This happens when
// the sensor records kernel-level probes for paths that can never resolve —
// e.g. Apache's .htaccess scan emits openat("foo.php/.htaccess") where
// foo.php is a regular file.  These paths should be skipped, not failed.
func isNotDirErr(err error) bool {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return errors.Is(pathErr.Err, syscall.ENOTDIR)
	}
	return errors.Is(err, syscall.ENOTDIR)
}
