package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tracepod/tracepod/hardener"
)

// runExtract implements the "hardener extract" subcommand (M4).
// It pulls an OCI image, extracts the files listed in a sensor manifest,
// resolves ELF shared-library dependencies, and writes the complete file
// tree to a destination directory on disk.
func runExtract(args []string) int {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	var (
		manifestPath = fs.String("manifest", "", "Path to manifest JSON produced by the sensor (required)")
		imageRef     = fs.String("image", "", "OCI image reference, e.g. nginx:1.25-alpine (required)")
		outputDir    = fs.String("output", "", "Destination directory for extracted file tree (required)")
		platform     = fs.String("platform", "linux/amd64", "Image platform, e.g. linux/amd64 or linux/arm64")
		username     = fs.String("username", "", "Registry username (overrides keychain when combined with --password)")
		password     = fs.String("password", "", "Registry password (overrides keychain when combined with --username)")
		insecure     = fs.Bool("insecure", false, "Skip TLS certificate verification")
		workDir      = fs.String("work-dir", "", "Temp directory for staging (default: system temp)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *manifestPath == "" || *imageRef == "" || *outputDir == "" {
		fs.Usage()
		fmt.Fprintln(os.Stderr, "error: --manifest, --image, and --output are required")
		return 1
	}

	m, err := loadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load manifest %s: %v\n", *manifestPath, err)
		return 1
	}

	isExplicit := *username != "" && *password != ""
	var opts hardener.PullOptions
	opts.Platform = *platform
	opts.Insecure = *insecure
	if isExplicit {
		opts.Keychain = hardener.NewExplicitKeychain(*username, *password)
	} else {
		opts.Keychain = hardener.NewKeychain()
	}

	authSource := hardener.DetectAuthSource(*imageRef, opts.Keychain, isExplicit)
	registry := registryFromRef(*imageRef)
	ctx := context.Background()

	stagingDir, err := os.MkdirTemp(*workDir, "tracepod-staging-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create staging dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(stagingDir)

	missing, err := hardener.ExtractFromImage(ctx, *imageRef, m, stagingDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: extract from image: %v\n", err)
		return 1
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "note: %d manifest path(s) not found in image layers (ENOENT probes):\n", len(missing))
		for _, p := range missing {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
	}
	extractedFromManifest := len(m.Files) - len(missing)

	added, unresolved, err := hardener.ResolveELFDependencies(stagingDir, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolve ELF dependencies: %v\n", err)
		return 1
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: create output dir: %v\n", err)
		return 1
	}
	if err := hardener.CopyFileSet(m, stagingDir, *outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: copy file set: %v\n", err)
		return 1
	}

	fmt.Printf("Registry:    %s\n", registry)
	fmt.Printf("Auth:        %s\n", authSource)
	fmt.Printf("Extracted:   %d files from manifest\n", extractedFromManifest)
	fmt.Printf("ELF deps:    %d additional libraries resolved\n", len(added))
	fmt.Printf("Total:       %d files in %s\n", extractedFromManifest+len(added), *outputDir)
	fmt.Printf("Unresolved:  %d DT_NEEDED entries\n", len(unresolved))

	if len(unresolved) > 0 {
		fmt.Fprintf(os.Stderr, "\nunresolved DT_NEEDED entries:\n")
		for _, u := range unresolved {
			fmt.Fprintf(os.Stderr, "  %s\n", u)
		}
		return 1
	}
	return 0
}
