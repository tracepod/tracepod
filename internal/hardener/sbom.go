package hardener

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// execCommandContext is the exec.CommandContext constructor used by
// GenerateSBOM and signSBOM. Replaced in tests to avoid real subprocess calls.
var execCommandContext = exec.CommandContext

// GenerateSBOM runs syft against the OCI layout in outputDir and writes
//
//	<outputDir>/sbom.cyclonedx.json
//	<outputDir>/sbom.spdx.json
//
// alongside the existing OCI layout blobs. sourceImage is the original image
// reference (e.g. "nginx:1.25-alpine"); when non-empty it is passed to syft as
// --source-name so the SBOM names the image correctly instead of using the
// local directory path. If signKey is non-empty, each SBOM file is signed with
// cosign and a .sig sidecar is written next to it.
//
// Returns an error if syft is not found in PATH. SBOM failure is non-fatal
// from the caller's perspective — the OCI image has already been written.
func GenerateSBOM(ctx context.Context, outputDir, sourceImage, signKey string) error {
	syftPath, err := exec.LookPath("syft")
	if err != nil {
		return fmt.Errorf("syft not found in PATH (install from https://github.com/anchore/syft): %w", err)
	}

	cyclonedxOut := filepath.Join(outputDir, "sbom.cyclonedx.json")
	spdxOut := filepath.Join(outputDir, "sbom.spdx.json")

	// syft oci-dir:<path> writes SBOMs to the named output files.
	// stdout is discarded (SBOMs go to files, not stdout).
	// stderr carries syft's progress output; route it to our stderr.
	args := []string{"oci-dir:" + outputDir}
	if sourceImage != "" {
		args = append(args, "--source-name", sourceImage)
	}
	args = append(args,
		"--output", "cyclonedx-json="+cyclonedxOut,
		"--output", "spdx-json="+spdxOut,
	)
	cmd := execCommandContext(ctx, syftPath, args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("syft: %w", err)
	}

	if signKey != "" {
		for _, sbomPath := range []string{cyclonedxOut, spdxOut} {
			if err := signSBOM(ctx, sbomPath, signKey); err != nil {
				return err
			}
		}
	}
	return nil
}

// signSBOM signs a single SBOM file with cosign, writing a .sig sidecar next
// to the input file.
func signSBOM(ctx context.Context, sbomPath, keyPath string) error {
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		return fmt.Errorf("cosign not found in PATH (install from https://github.com/sigstore/cosign): %w", err)
	}

	cmd := execCommandContext(ctx, cosignPath,
		"sign-blob",
		"--key", keyPath,
		"--output-signature", sbomPath+".sig",
		sbomPath,
	)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign sign %s: %w", filepath.Base(sbomPath), err)
	}
	return nil
}
