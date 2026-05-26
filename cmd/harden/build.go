package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tracepod/tracepod/hardener"
	"github.com/tracepod/tracepod/manifest"
)

// multiFlag is a repeatable string flag (e.g. --include can be given multiple
// times on the command line). flag.FlagSet does not support this natively.
type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

// runBuild implements the "harden build" subcommand.
// It assembles a FROM-scratch OCI image from the sensor manifest, writes it
// as an OCI layout to --output, and optionally pushes to --push.
func runBuild(args []string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	var (
		manifestPath       = fs.String("manifest", "", "Path to manifest JSON produced by the sensor (required)")
		sourceRef          = fs.String("source", "", "OCI image reference used during profiling, e.g. nginx:1.25-alpine (required)")
		outputDir          = fs.String("output", "", "Destination directory for the OCI layout (required)")
		pushRef            = fs.String("push", "", "Push the image to this registry reference after building, e.g. 123.dkr.ecr.eu-west-1.amazonaws.com/app:hardened")
		base               = fs.String("base", "scratch", "Base image (only 'scratch' is currently implemented)")
		platform           = fs.String("platform", "linux/amd64", "Image platform, e.g. linux/amd64 or linux/arm64 — must match your deployment target")
		username           = fs.String("username", "", "Registry username (overrides keychain when combined with --password)")
		password           = fs.String("password", "", "Registry password (overrides keychain when combined with --username)")
		insecure           = fs.Bool("insecure", false, "Skip TLS certificate verification")
		workDir            = fs.String("work-dir", "", "Temp directory for staging (default: system temp)")
		minProfileDuration = fs.Duration("min-profile-duration", manifest.DefaultMinProfileDuration, "Minimum recommended profiling window for confidence scoring")
		verbose            = fs.Bool("verbose", false, "Print full confidence penalty breakdown and ELF audit warnings")
		sbom               = fs.Bool("sbom", false, "Generate CycloneDX and SPDX SBOMs via syft into the --output directory")
		sbomSignKey        = fs.String("sbom-sign-key", "", "Path to cosign private key for signing SBOMs (requires --sbom)")
		includePaths multiFlag
		mkdirs       multiFlag
		touches      multiFlag
	)
	fs.Var(&includePaths, "include", "Force-include all files under this in-image directory path (repeatable, e.g. --include /usr/share/nginx/html)")
	fs.Var(&mkdirs, "mkdir", "Create an empty directory in the hardened image even if absent from source (repeatable, e.g. --mkdir /var/cache/nginx/client_temp)")
	fs.Var(&touches, "touch", "Create an empty 0-byte file in the hardened image if absent from source (repeatable, e.g. --touch /run/nginx.pid)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	if *manifestPath == "" || *sourceRef == "" || *outputDir == "" {
		fs.Usage()
		fmt.Fprintln(os.Stderr, "error: --manifest, --source, and --output are required")
		return 1
	}

	if (*username == "") != (*password == "") {
		fmt.Fprintln(os.Stderr, "error: --username and --password must both be set or both be empty")
		return 1
	}

	if *base != "scratch" {
		fmt.Fprintf(os.Stderr, "error: --base %q is not yet supported; only 'scratch' is implemented\n", *base)
		return 1
	}

	m, err := loadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load manifest %s: %v\n", *manifestPath, err)
		return 1
	}

	isExplicit := *username != "" && *password != ""
	var kc = hardener.NewKeychain()
	if isExplicit {
		kc = hardener.NewExplicitKeychain(*username, *password)
	}

	authSource := hardener.DetectAuthSource(*sourceRef, kc, isExplicit)
	registry := registryFromRef(*sourceRef)
	ctx := context.Background()

	var ensurePaths []hardener.EnsureEntry
	for _, d := range mkdirs {
		ensurePaths = append(ensurePaths, hardener.EnsureEntry{Path: d, IsDir: true})
	}
	for _, f := range touches {
		ensurePaths = append(ensurePaths, hardener.EnsureEntry{Path: f, IsDir: false})
	}

	opts := hardener.BuildOptions{
		Platform:     *platform,
		Keychain:     kc,
		Insecure:     *insecure,
		WorkDir:      *workDir,
		PushRef:      *pushRef,
		IncludePaths: includePaths,
		EnsurePaths:  ensurePaths,
	}

	result, err := hardener.BuildImage(ctx, *sourceRef, m, *outputDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Compute confidence before printing (manifest was mutated by BuildImage).
	confidence := manifest.ComputeConfidence(m, *minProfileDuration)

	// Print result summary.
	directCount, inferredCount, manualCount, dirInclusionCount := countBySources(m)
	fmt.Printf("Source:      %s (%s)\n", *sourceRef, result.Digest)
	fmt.Printf("Auth:        %s\n", authSource)
	fmt.Printf("Registry:    %s\n", registry)
	if dirInclusionCount > 0 {
		fmt.Printf("Files:       %d (%d direct, %d inferred-elf, %d manual/scratch-compat, %d directory-inclusion)\n",
			result.FileCount, directCount, inferredCount, manualCount, dirInclusionCount)
	} else {
		fmt.Printf("Files:       %d (%d direct, %d inferred-elf, %d manual/scratch-compat)\n",
			result.FileCount, directCount, inferredCount, manualCount)
	}
	if result.EnsuredCount > 0 {
		fmt.Printf("Ensured:     %d explicitly created (--mkdir / --touch)\n", result.EnsuredCount)
	}
	fmt.Printf("Confidence:  %s\n", formatConfidence(confidence, *verbose))
	fmt.Printf("Layer:       %s (%s)\n", humanBytes(result.LayerSize), result.LayerDigest)
	fmt.Printf("OCI layout:  %s\n", *outputDir)
	if !result.Pushed {
		fmt.Printf("Next:        skopeo copy oci:%s docker-daemon:myapp:hardened\n", *outputDir)
		fmt.Printf("             # or push directly: harden build ... --push <registry>/<image>:<tag>\n")
	}

	// Verbose: full penalty breakdown and orphan inferred-elf audit.
	if *verbose && len(confidence.Penalties) > 0 {
		fmt.Println("             Penalty breakdown:")
		for _, p := range confidence.Penalties {
			fmt.Printf("               %s (%+d): %s\n", p.Signal, p.Points, p.Reason)
		}
	}
	if *verbose && len(confidence.OrphanInferred) > 0 {
		fmt.Printf("             Audit: %d inferred-elf %s whose parent binary has no direct entry (expected if dynamic linker opened the library):\n",
			len(confidence.OrphanInferred), pluralStr(len(confidence.OrphanInferred), "entry", "entries"))
		for _, p := range confidence.OrphanInferred {
			fmt.Printf("               %s\n", p)
		}
	}

	for _, w := range result.ScratchWarnings {
		fmt.Printf("Warning:     %s\n", w)
	}
	for _, mp := range result.MissingIncludes {
		fmt.Printf("Warning:     --include %s: not found in source image (directory may be created at runtime)\n", mp)
	}
	if confidence.Level == manifest.ConfidenceVeryLow {
		fmt.Printf("Warning:     confidence score is Very Low — image may be missing runtime-critical files; run with --verbose for details\n")
	}

	if result.Pushed {
		fmt.Printf("Pushed:      %s (%s)\n", result.PushedRef, result.Digest)
	}

	if *sbom {
		if err := hardener.GenerateSBOM(ctx, *outputDir, *sourceRef, *sbomSignKey); err != nil {
			fmt.Fprintf(os.Stderr, "warning: sbom generation failed: %v\n", err)
		} else {
			fmt.Printf("SBOM:        %s/sbom.cyclonedx.json\n", *outputDir)
			fmt.Printf("             %s/sbom.spdx.json\n", *outputDir)
		}
	}

	if len(result.Unresolved) > 0 {
		fmt.Fprintf(os.Stderr, "\nunresolved DT_NEEDED entries:\n")
		for _, u := range result.Unresolved {
			fmt.Fprintf(os.Stderr, "  %s\n", u)
		}
		return 1
	}

	// Exit 2 for any scratch-compat warning that is not resolv.conf — resolv.conf
	// absence is expected because the container runtime bind-mounts it at startup.
	for _, w := range result.ScratchWarnings {
		if !containsStr(w, "resolv.conf") {
			return 2
		}
	}

	return 0
}

// countBySources tallies manifest entries by observation source.
func countBySources(m *manifest.Manifest) (direct, inferred, manual, dirInclusion int) {
	for _, e := range m.Files {
		switch e.Source {
		case manifest.SourceDirect:
			direct++
		case manifest.SourceInferredELF:
			inferred++
		case manifest.SourceManual:
			manual++
		case manifest.SourceDirectoryInclusion:
			dirInclusion++
		}
	}
	return
}

// formatConfidence formats the confidence result for the Confidence: output line.
// With verbose=false the inline summary lists at most 2 penalties.
func formatConfidence(r manifest.ConfidenceResult, verbose bool) string {
	base := fmt.Sprintf("%d/100 (%s)", r.Score, r.Level)
	if len(r.Penalties) == 0 {
		return base
	}
	// Inline summary: cap at 2 penalties to avoid line-wrapping in terminals.
	summaries := make([]string, 0, 2)
	for i, p := range r.Penalties {
		if i >= 2 {
			break
		}
		summaries = append(summaries, p.Reason)
	}
	suffix := strings.Join(summaries, "; ")
	if len(r.Penalties) > 2 && !verbose {
		suffix += fmt.Sprintf(" (+%d more, use --verbose)", len(r.Penalties)-2)
	}
	return base + " — " + suffix
}

// pluralStr returns singular if n == 1, otherwise plural.
func pluralStr(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// humanBytes formats a byte count as a human-readable string (KB/MB).
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// containsStr reports whether s contains sub.
func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
