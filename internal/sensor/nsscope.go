package sensor

import (
	"fmt"
	"path"
	"strings"
)

// NamespaceScope limits profiling to chosen Kubernetes namespaces
// (--namespaces-include / --namespaces-exclude).
//
// Rules:
//   - An empty include list means every namespace.
//   - Exclude wins over include.
//   - Entries are exact names or glob patterns (path.Match syntax: "*", "?",
//     "[...]"); namespace names never contain "/", so "*" matches any run of
//     characters.
//   - A container whose namespace is unknown (no pod metadata) is out of scope
//     when an include list is set, and in scope otherwise.
//
// The zero value and a nil *NamespaceScope allow everything.
type NamespaceScope struct {
	include []string
	exclude []string
}

// NewNamespaceScope parses comma-separated include and exclude lists. Spaces
// around entries and empty entries are ignored. It returns an error for a
// malformed glob pattern.
func NewNamespaceScope(include, exclude string) (*NamespaceScope, error) {
	inc, err := parseNamespaceList("--namespaces-include", include)
	if err != nil {
		return nil, err
	}
	exc, err := parseNamespaceList("--namespaces-exclude", exclude)
	if err != nil {
		return nil, err
	}
	return &NamespaceScope{include: inc, exclude: exc}, nil
}

func parseNamespaceList(flagName, s string) ([]string, error) {
	var out []string
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, err := path.Match(e, ""); err != nil {
			return nil, fmt.Errorf("%s: bad pattern %q: %w", flagName, e, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// Allows reports whether containers in namespace ns may be profiled. ns == ""
// means the namespace is unknown.
func (s *NamespaceScope) Allows(ns string) bool {
	if s == nil {
		return true
	}
	if ns == "" {
		return len(s.include) == 0
	}
	if matchAny(s.exclude, ns) {
		return false
	}
	return len(s.include) == 0 || matchAny(s.include, ns)
}

// IsAll reports whether the scope allows every namespace (no include and no
// exclude entries).
func (s *NamespaceScope) IsAll() bool {
	return s == nil || (len(s.include) == 0 && len(s.exclude) == 0)
}

// String describes the effective scope for the startup log.
func (s *NamespaceScope) String() string {
	if s.IsAll() {
		return "all namespaces"
	}
	inc := "all"
	if len(s.include) > 0 {
		inc = strings.Join(s.include, ",")
	}
	exc := "none"
	if len(s.exclude) > 0 {
		exc = strings.Join(s.exclude, ",")
	}
	return fmt.Sprintf("include=%s exclude=%s", inc, exc)
}

func matchAny(patterns []string, ns string) bool {
	for _, p := range patterns {
		// Patterns were validated in NewNamespaceScope, so err is always nil.
		if ok, _ := path.Match(p, ns); ok {
			return true
		}
	}
	return false
}
