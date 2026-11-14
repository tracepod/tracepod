// Package hygiene holds repository-wide checks that are not tied to one package.
package hygiene

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoPrivateNamesInTrackedFiles fails if any tracked file mentions a
// private name. The pattern is built from parts so this file does not match.
func TestNoPrivateNamesInTrackedFiles(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	dir := strings.TrimSpace(string(root))

	out, err := exec.Command("git", "-C", dir, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	pat := regexp.MustCompile("(?i)" + strings.Join([]string{"nee" + "va", "ebpf" + "-hardener", "jose" + "mota", "diogo" + "mota"}, "|"))
	self := "internal/hygiene/names_test.go"

	for _, rel := range bytes.Split(out, []byte{0}) {
		name := string(rel)
		if name == "" || name == self {
			continue
		}
		if pat.MatchString(name) {
			t.Errorf("%s: path matches a private name", name)
			continue
		}
		// git grep skips binary files and files deleted from the work tree.
		g := exec.Command("git", "-C", dir, "grep", "-nIiE", pat.String()[4:], "--", filepath.ToSlash(name))
		if b, _ := g.Output(); len(b) > 0 {
			t.Errorf("%s contains a private name:\n%s", name, b)
		}
	}
}
