// Command harden is the Tracepod image hardener CLI.
//
// Subcommands:
//
//	extract  Pull an OCI image, extract the manifest file set, resolve ELF deps
//	         and write the file tree to disk. (M4)
//
//	build    Assemble a FROM-scratch OCI image from a sensor manifest, write it
//	         as an OCI layout, and optionally push to a registry. (M5/M6)
//
//	version  Print version information and exit.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tracepod/tracepod/manifest"
)

// version and commit are set at build time via -ldflags:
//
//	-X main.version=v0.1.0 -X main.commit=abc1234
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "extract":
		os.Exit(runExtract(os.Args[2:]))
	case "build":
		os.Exit(runBuild(os.Args[2:]))
	case "version", "--version", "-version":
		fmt.Printf("harden version %s (commit %s)\n", version, commit)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: harden <subcommand> [flags]

Subcommands:
  extract   Pull an OCI image and extract the sensor manifest file set to disk
  build     Build a FROM-scratch OCI image from a sensor manifest
  version   Print version information

Run "harden <subcommand> -help" for subcommand flags.

Version: %s (commit %s)
`, version, commit)
}

// loadManifest reads and JSON-decodes a sensor manifest from path.
func loadManifest(path string) (*manifest.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if m.Files == nil {
		m.Files = make(map[string]manifest.FileEntry)
	}
	return &m, nil
}

// registryFromRef extracts the registry hostname from an image reference.
// Falls back to "docker.io" for short references like "nginx:1.25".
func registryFromRef(imageRef string) string {
	parts := splitRef(imageRef)
	if len(parts) >= 2 {
		host := parts[0]
		if isRegistryHost(host) {
			return host
		}
	}
	return "docker.io"
}

func splitRef(ref string) []string {
	at := lastByte(ref, '@')
	if at > 0 {
		ref = ref[:at]
	} else if colon := lastByte(ref, ':'); colon > lastByte(ref, '/') {
		ref = ref[:colon]
	}
	slash := firstByte(ref, '/')
	if slash < 0 {
		return []string{ref}
	}
	return []string{ref[:slash], ref[slash+1:]}
}

func isRegistryHost(s string) bool {
	if s == "localhost" {
		return true
	}
	for _, c := range s {
		if c == '.' || c == ':' {
			return true
		}
	}
	return false
}

func lastByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func firstByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
