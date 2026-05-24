package manifest

import (
	"path/filepath"
	"strings"
)

// DenyList filters out file paths that are high-frequency noise and should
// never appear in a manifest: kernel virtual filesystems, temporary files,
// log files, and runtime sockets.
//
// Three rule types are supported:
//   - Directory prefix: any path under the directory is denied (e.g. "/proc/")
//   - Extension suffix: any path with this suffix is denied (e.g. ".log")
//   - Glob pattern: filepath.Match pattern for exact path matching
//
// Use DefaultDenyList() for the standard noise set; call Add to extend it.
type DenyList struct {
	dirPrefixes  []string // paths with these prefixes (including the trailing slash) are denied
	fileSuffixes []string // paths ending with these suffixes are denied
	patterns     []string // filepath.Match patterns for fixed-depth matching
}

// DefaultDenyList returns a DenyList pre-loaded with standard noise patterns.
func DefaultDenyList() *DenyList {
	d := &DenyList{}
	// Directory prefixes — match any path under these virtual/ephemeral dirs
	d.dirPrefixes = []string{
		"/proc/",
		"/sys/",
		"/dev/",
		"/run/",
		"/var/run/",
		"/tmp/",
	}
	// File suffixes — log files at any path depth
	d.fileSuffixes = []string{
		".log",
	}
	// Patterns — rotated logs (.log.1, .log.2026-04-04, etc.)
	d.patterns = []string{
		"*.log.*",
	}
	return d
}

// NewDenyList returns an empty DenyList. Use Add to populate it.
func NewDenyList() *DenyList {
	return &DenyList{}
}

// Add appends rules to the deny list. Rule interpretation:
//   - Ends with "/" or "/*" or "/**": treated as a directory prefix
//     (any path under that directory is denied)
//   - Starts with "*.": treated as a file suffix (denies paths ending with the suffix)
//   - Otherwise: treated as a filepath.Match glob pattern
func (d *DenyList) Add(rules ...string) {
	for _, rule := range rules {
		switch {
		case strings.HasSuffix(rule, "/**") || strings.HasSuffix(rule, "/*"):
			// Strip the trailing glob and normalise to a prefix ending with /
			prefix := strings.TrimSuffix(strings.TrimSuffix(rule, "/**"), "/*")
			prefix = strings.TrimSuffix(prefix, "/") + "/"
			d.dirPrefixes = append(d.dirPrefixes, prefix)
		case strings.HasSuffix(rule, "/"):
			d.dirPrefixes = append(d.dirPrefixes, rule)
		case strings.HasPrefix(rule, "*.") && !strings.Contains(rule[2:], "."):
			// Simple extension pattern like "*.log"
			d.fileSuffixes = append(d.fileSuffixes, rule[1:]) // strip the leading *
		default:
			d.patterns = append(d.patterns, rule)
		}
	}
}

// Allow returns true if path should be recorded in the manifest.
// Returns false if the path matches any deny rule.
func (d *DenyList) Allow(path string) bool {
	// Check directory prefixes
	for _, prefix := range d.dirPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	// Check file suffixes
	for _, suffix := range d.fileSuffixes {
		if strings.HasSuffix(path, suffix) {
			return false
		}
	}
	// Check glob patterns against the full path and just the filename
	base := filepath.Base(path)
	for _, pat := range d.patterns {
		if matched, err := filepath.Match(pat, base); err == nil && matched {
			return false
		}
		if matched, err := filepath.Match(pat, path); err == nil && matched {
			return false
		}
	}
	return true
}
