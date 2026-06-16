package hardener

// removal.go produces the removed-set: every OS package present in the SOURCE
// image and entirely ABSENT from the hardened image, with the source-image file
// paths that drove each removal. It is the OSS-3 producer for the WP3 removal-VEX
// contract; the controller consumes this verbatim to emit component_not_present
// attestations for the hardened image without ever re-scanning it.
//
// Contract identity is shared with the controller (WP3). A change to the emitted
// shape is a breaking change to the OSS-3 <-> WP3 contract: bump
// RemovalManifestSchemaVersion and add a new docs/removal-manifest-schema file in
// lockstep. The fields the controller actually deserialises are documented in
// docs/removal-manifest-schema/README.md as the "consumed subset".
//
// Facts only (R2). This manifest states a set-difference: a package whose owned
// files are all absent from the hardened image. It carries NO reachability,
// runtime, justification, or VEX vocabulary — the consumer decides what removal
// means. CVE association is the controller's job (it owns the findings source),
// which is why no findings/scanner field appears here.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// Removal-manifest contract identity. Kept in lockstep with the controller's
// RemovalManifestSchema / RemovalManifestSchemaVersion (WP3 owns the contract).
const (
	RemovalManifestSchema        = "tracepod.dev/removal-manifest"
	RemovalManifestSchemaVersion = "1.0"
	// RemovalManifestFilename is written into the OCI output directory alongside
	// the SBOMs, travelling through the same handoff channel (R4).
	RemovalManifestFilename = "removal-manifest.json"
)

// RemovalManifest is the per-build removed-set. The fields schema, schema_version,
// source_digest, hardened_digest, hardened_ref and removed are the contract
// consumed by the controller (WP3). source_platform and tooling are additive
// OSS-3 audit metadata the controller ignores (R1/R3); they never affect removal
// VEX.
type RemovalManifest struct {
	Schema         string           `json:"schema"`
	SchemaVersion  string           `json:"schema_version"`
	SourceDigest   string           `json:"source_digest,omitempty"`
	SourcePlatform string           `json:"source_platform,omitempty"`
	HardenedDigest string           `json:"hardened_digest"`
	HardenedRef    string           `json:"hardened_ref,omitempty"`
	Tooling        RemovalTooling   `json:"tooling"`
	Removed        []RemovedPackage `json:"removed"`
}

// RemovalTooling records the versions of the tools that produced the removed-set,
// for audit. Additive (not part of the WP3-consumed subset).
type RemovalTooling struct {
	Hardener string `json:"hardener,omitempty"`
	Syft     string `json:"syft,omitempty"`
}

// RemovedPackage is one package the hardener stripped: present in the source
// image, none of its files retained. Purl is the package-url from the source
// SBOM; Paths are the source-image paths whose absence in the hardened image is
// the evidence of removal (never a runtime claim).
type RemovedPackage struct {
	Purl    string   `json:"purl"`
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

// SourcePackage is one package cataloged from the source image, with the absolute
// in-image paths it owns. Produced by scanning the extracted source filesystem
// (the digest-pinned staging tree) with syft.
type SourcePackage struct {
	Purl    string
	Name    string
	Version string
	Paths   []string
}

// ComputeRemovedSet returns, for the given source packages, those whose owned
// paths are ENTIRELY absent from retained — the set-difference at the heart of
// OSS-3 (R2).
//
//   - retained holds the absolute in-image paths kept in the hardened image
//     (the finalised manifest file set).
//   - A package with ANY retained owned path is excluded: partial retention is
//     NOT removal (R2). Multi-owner files fall out of this naturally — if a
//     shared file is retained, every package owning it is retained.
//   - A package with zero owned paths is skipped: with no file evidence there is
//     nothing to prove absent. (Language-ecosystem packages that syft catalogs
//     without an owned-file list therefore never appear; only file-owning OS
//     packages can be proven removed by absence.)
//
// Output is deterministic: removed packages sorted by purl, evidence paths sorted
// and de-duplicated.
func ComputeRemovedSet(sources []SourcePackage, retained map[string]struct{}) []RemovedPackage {
	out := make([]RemovedPackage, 0, len(sources))
	for _, p := range sources {
		paths := uniqueSortedPaths(p.Paths)
		if len(paths) == 0 {
			continue // no file evidence — cannot prove removal
		}
		retainedAny := false
		for _, path := range paths {
			if _, ok := retained[path]; ok {
				retainedAny = true
				break
			}
		}
		if retainedAny {
			continue // partially (or fully) retained — not removed (R2)
		}
		out = append(out, RemovedPackage{
			Purl:    p.Purl,
			Name:    p.Name,
			Version: p.Version,
			Paths:   paths,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out
}

// RetainedSetFromKeys builds the retained-path lookup from the finalised manifest
// path keys (m.Files keys). Paths are normalised the same way scanned source
// paths are, so the two sets intersect correctly.
func RetainedSetFromKeys(paths []string) map[string]struct{} {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[normalizeImagePath(p)] = struct{}{}
	}
	return set
}

// GenerateRemovalManifest scans the extracted source filesystem rootDir for OS
// packages, computes the removed-set against the retained path set, and assembles
// a schema-valid RemovalManifest. It performs no analysis the pipeline has not
// already done beyond the source package catalog (R2: serialise existing
// knowledge).
//
// rootDir MUST be the staging tree extracted from the same source digest the
// build consumed, so the package view and the file view are provably of one
// image (no re-pull, no re-resolve).
func GenerateRemovalManifest(ctx context.Context, rootDir string, retained map[string]struct{}, meta RemovalMeta) (*RemovalManifest, error) {
	sources, syftVersion, err := scanSourcePackages(ctx, rootDir)
	if err != nil {
		return nil, err
	}
	return &RemovalManifest{
		Schema:         RemovalManifestSchema,
		SchemaVersion:  RemovalManifestSchemaVersion,
		SourceDigest:   meta.SourceDigest,
		SourcePlatform: meta.SourcePlatform,
		HardenedDigest: meta.HardenedDigest,
		HardenedRef:    meta.HardenedRef,
		Tooling: RemovalTooling{
			Hardener: meta.HardenerVersion,
			Syft:     syftVersion,
		},
		Removed: ComputeRemovedSet(sources, retained),
	}, nil
}

// RemovalMeta carries the per-build identity fields the manifest records.
type RemovalMeta struct {
	SourceDigest    string
	SourcePlatform  string
	HardenedDigest  string
	HardenedRef     string
	HardenerVersion string
}

// WriteRemovalManifest writes m as indented JSON to
// <outputDir>/removal-manifest.json (adjacent to the SBOMs, R4).
func WriteRemovalManifest(outputDir string, m *RemovalManifest) (string, error) {
	path := filepath.Join(outputDir, RemovalManifestFilename)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal removal manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write removal manifest: %w", err)
	}
	return path, nil
}

// scanSourcePackages runs syft against the extracted source filesystem in rootDir
// and returns the cataloged packages with their owned file paths, plus the syft
// version that produced them. It reuses the syft binary already required for SBOM
// generation; the OS catalogers (dpkg/apk/rpm) populate per-package owned-file
// lists from the package databases present in the full staging tree.
func scanSourcePackages(ctx context.Context, rootDir string) ([]SourcePackage, string, error) {
	syftPath, err := exec.LookPath("syft")
	if err != nil {
		return nil, "", fmt.Errorf("syft not found in PATH (install from https://github.com/anchore/syft): %w", err)
	}

	// syft-json carries both artifacts[].purl and per-package metadata.files[].path
	// for OS catalogers, plus descriptor.version (the syft version). Emit to stdout.
	cmd := execCommandContext(ctx, syftPath, "scan", "dir:"+rootDir, "-o", "syft-json")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("syft scan source: %w", err)
	}
	return parseSyftPackages(out)
}

// syftDocument is the minimal subset of syft-json we read.
type syftDocument struct {
	Artifacts  []syftArtifact `json:"artifacts"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type syftArtifact struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Type     string          `json:"type"`
	PURL     string          `json:"purl"`
	Metadata json.RawMessage `json:"metadata"`
}

// syftMetadataFiles matches the owned-file list emitted by the dpkg/apk/rpm
// catalogers under metadata.files[].path.
type syftMetadataFiles struct {
	Files []struct {
		Path string `json:"path"`
	} `json:"files"`
}

// parseSyftPackages extracts SourcePackages from a syft-json document. Packages
// with a purl are returned; their owned paths come from metadata.files[].path
// (empty for ecosystems that do not record file ownership). The syft version is
// taken from the document descriptor.
func parseSyftPackages(data []byte) ([]SourcePackage, string, error) {
	var doc syftDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("parse syft-json: %w", err)
	}
	pkgs := make([]SourcePackage, 0, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		if a.PURL == "" {
			continue
		}
		var mf syftMetadataFiles
		if len(a.Metadata) > 0 {
			_ = json.Unmarshal(a.Metadata, &mf) // best-effort: not all metadata shapes carry files
		}
		var paths []string
		for _, f := range mf.Files {
			if f.Path != "" {
				paths = append(paths, normalizeImagePath(f.Path))
			}
		}
		pkgs = append(pkgs, SourcePackage{
			Purl:    a.PURL,
			Name:    a.Name,
			Version: a.Version,
			Paths:   paths,
		})
	}
	return pkgs, doc.Descriptor.Version, nil
}

// normalizeImagePath canonicalises an in-image path so source-scan paths and
// manifest file keys compare equal: cleaned and rooted with a single leading
// slash.
func normalizeImagePath(p string) string {
	if p == "" {
		return p
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return filepath.Clean(p)
}

// uniqueSortedPaths normalises, de-duplicates and sorts a path slice.
func uniqueSortedPaths(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		n := normalizeImagePath(p)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
