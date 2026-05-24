package hardener

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBin writes a shell script to dir/<name> that exits with the given code.
func fakeBin(t *testing.T, dir, name string, exitCode int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\nexit 0\n"
	if exitCode != 0 {
		script = "#!/bin/sh\necho 'fake error' >&2\nexit 1\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// withMockExec replaces execCommandContext for the duration of the test,
// running absPath (an absolute binary path) instead of whatever the real
// command would be. Captured contains the args passed by the caller.
func withMockExec(t *testing.T, absPath string) *[][]string {
	t.Helper()
	var calls [][]string
	orig := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		return exec.CommandContext(ctx, absPath)
	}
	t.Cleanup(func() { execCommandContext = orig })
	return &calls
}

// ── syft not-in-PATH ─────────────────────────────────────────────────────────

// TestGenerateSBOM_SyftNotInPATH verifies that GenerateSBOM returns a clear
// error when syft is absent from PATH, without panicking or producing partial
// output.
func TestGenerateSBOM_SyftNotInPATH(t *testing.T) {
	t.Setenv("PATH", "")
	err := GenerateSBOM(context.Background(), t.TempDir(), "", "")
	if err == nil {
		t.Fatal("expected error when syft not in PATH, got nil")
	}
	if !strings.Contains(err.Error(), "syft not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ── syft args ────────────────────────────────────────────────────────────────

// TestGenerateSBOM_InvokesCorrectArgs verifies that GenerateSBOM invokes syft
// with the oci-dir scheme and both --output flags pointing into outputDir.
func TestGenerateSBOM_InvokesCorrectArgs(t *testing.T) {
	fakebin := t.TempDir()
	fakeSyft := fakeBin(t, fakebin, "syft", 0)
	t.Setenv("PATH", fakebin)

	dir := t.TempDir()
	calls := withMockExec(t, fakeSyft)

	if err := GenerateSBOM(context.Background(), dir, "nginx:1.25-alpine", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*calls) == 0 {
		t.Fatal("syft was not invoked")
	}
	args := (*calls)[0]

	// Source must use oci-dir: scheme.
	if !strings.HasPrefix(args[1], "oci-dir:") {
		t.Errorf("expected oci-dir: source arg, got %q", args[1])
	}

	joined := strings.Join(args, " ")

	// --source-name must be present with the image reference.
	if !strings.Contains(joined, "--source-name") {
		t.Error("missing --source-name flag")
	}
	if !strings.Contains(joined, "nginx:1.25-alpine") {
		t.Error("missing source image reference in args")
	}

	if !strings.Contains(joined, "cyclonedx-json=") {
		t.Error("missing cyclonedx-json output arg")
	}
	if !strings.Contains(joined, "spdx-json=") {
		t.Error("missing spdx-json output arg")
	}

	// Output paths must land inside outputDir.
	for _, arg := range args {
		if strings.HasPrefix(arg, "cyclonedx-json=") || strings.HasPrefix(arg, "spdx-json=") {
			path := strings.SplitN(arg, "=", 2)[1]
			if !strings.HasPrefix(path, dir) {
				t.Errorf("output path %q outside outputDir %q", path, dir)
			}
		}
	}
}

// ── syft failure is returned as error ────────────────────────────────────────

// TestGenerateSBOM_SyftFailure verifies that a non-zero syft exit propagates
// as an error (callers in build.go treat it as a non-fatal warning).
func TestGenerateSBOM_SyftFailure(t *testing.T) {
	fakebin := t.TempDir()
	fakeSyftFail := fakeBin(t, fakebin, "syft", 1)
	t.Setenv("PATH", fakebin)
	withMockExec(t, fakeSyftFail)

	err := GenerateSBOM(context.Background(), t.TempDir(), "", "")
	if err == nil {
		t.Fatal("expected error from failing syft, got nil")
	}
	if !strings.Contains(err.Error(), "syft") {
		t.Errorf("error should mention syft: %v", err)
	}
}

// ── cosign not-in-PATH ───────────────────────────────────────────────────────

// TestSignSBOM_CosignNotInPATH verifies that signSBOM returns a clear error
// when cosign is absent from PATH.
func TestSignSBOM_CosignNotInPATH(t *testing.T) {
	t.Setenv("PATH", "")
	err := signSBOM(context.Background(), filepath.Join(t.TempDir(), "sbom.json"), "key.pem")
	if err == nil {
		t.Fatal("expected error when cosign not in PATH, got nil")
	}
	if !strings.Contains(err.Error(), "cosign not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ── cosign signature sidecar args ────────────────────────────────────────────

// TestSignSBOM_CreatesSignatureArg verifies that signSBOM passes
// --output-signature <file>.sig to cosign and includes the key path.
func TestSignSBOM_CreatesSignatureArg(t *testing.T) {
	fakebin := t.TempDir()
	fakeCosign := fakeBin(t, fakebin, "cosign", 0)
	t.Setenv("PATH", fakebin)
	calls := withMockExec(t, fakeCosign)

	sbomPath := filepath.Join(t.TempDir(), "sbom.cyclonedx.json")
	keyPath := "/keys/cosign.key"

	if err := signSBOM(context.Background(), sbomPath, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*calls) == 0 {
		t.Fatal("cosign was not invoked")
	}
	joined := strings.Join((*calls)[0], " ")

	if !strings.Contains(joined, "--output-signature") {
		t.Error("missing --output-signature flag")
	}
	if !strings.Contains(joined, sbomPath+".sig") {
		t.Errorf("expected signature path %q in args: %s", sbomPath+".sig", joined)
	}
	if !strings.Contains(joined, keyPath) {
		t.Errorf("expected key path %q in args: %s", keyPath, joined)
	}
}

// ── signing is called for both SBOM files ────────────────────────────────────

// TestGenerateSBOM_WithSigning verifies that when signKey is non-empty,
// cosign is invoked once per SBOM file (cyclonedx + spdx).
func TestGenerateSBOM_WithSigning(t *testing.T) {
	fakebin := t.TempDir()
	fakeSyft := fakeBin(t, fakebin, "syft", 0)
	fakeCosign := fakeBin(t, fakebin, "cosign", 0)
	t.Setenv("PATH", fakebin)

	var calls [][]string
	orig := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		// Route to the appropriate fake binary by checking the name suffix.
		if strings.HasSuffix(name, "cosign") {
			return exec.CommandContext(ctx, fakeCosign)
		}
		return exec.CommandContext(ctx, fakeSyft)
	}
	t.Cleanup(func() { execCommandContext = orig })

	if err := GenerateSBOM(context.Background(), t.TempDir(), "", "/keys/cosign.key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count cosign invocations.
	var cosignCalls int
	for _, c := range calls {
		if strings.HasSuffix(c[0], "cosign") {
			cosignCalls++
		}
	}
	if cosignCalls != 2 {
		t.Errorf("expected 2 cosign calls (one per SBOM), got %d", cosignCalls)
	}
}

// ── integration: real syft, content validity ─────────────────────────────────

// TestGenerateSBOM_Integration runs syft for real against a minimal OCI layout
// and validates that both output files are well-formed with correct schema
// markers. Skipped when syft is not installed or -short is set.
func TestGenerateSBOM_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed; skipping integration test")
	}

	outputDir := t.TempDir()
	m := nginxMinimalManifest()
	if _, err := BuildImage(t.Context(), "nginx:1.25-alpine", m, outputDir, BuildOptions{}); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if err := GenerateSBOM(context.Background(), outputDir, "nginx:1.25-alpine", ""); err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}

	// CycloneDX: must have bomFormat == "CycloneDX".
	cdxPath := filepath.Join(outputDir, "sbom.cyclonedx.json")
	cdxData, err := os.ReadFile(cdxPath)
	if err != nil {
		t.Fatalf("sbom.cyclonedx.json: %v", err)
	}
	var cdx struct {
		BomFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(cdxData, &cdx); err != nil {
		t.Fatalf("sbom.cyclonedx.json is not valid JSON: %v", err)
	}
	if cdx.BomFormat != "CycloneDX" {
		t.Errorf("bomFormat: want CycloneDX, got %q", cdx.BomFormat)
	}

	// SPDX: must have spdxVersion starting with "SPDX-".
	spdxPath := filepath.Join(outputDir, "sbom.spdx.json")
	spdxData, err := os.ReadFile(spdxPath)
	if err != nil {
		t.Fatalf("sbom.spdx.json: %v", err)
	}
	var spdx struct {
		SpdxVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(spdxData, &spdx); err != nil {
		t.Fatalf("sbom.spdx.json is not valid JSON: %v", err)
	}
	if !strings.HasPrefix(spdx.SpdxVersion, "SPDX-") {
		t.Errorf("spdxVersion: want SPDX-*, got %q", spdx.SpdxVersion)
	}
}
