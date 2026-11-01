package hardener

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInRoot(t *testing.T) {
	root := mkRoot(t, "usr/lib/sub", "etc")
	if err := os.WriteFile(filepath.Join(root, "usr/lib/real.so"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link(t, root, "/usr/lib", "lib")                          // abs dir link
	link(t, root, "real.so", "usr/lib/rel.so")                // relative file link
	link(t, root, "/lib/rel.so", "usr/lib/abs.so")            // abs link via dir link
	link(t, root, "../../../../../etc", "usr/lib/sub/escape") // clamped at root
	link(t, root, "loop", "usr/lib/loop")
	link(t, root, "b", "usr/lib/a")
	link(t, root, "a", "usr/lib/b")
	link(t, root, "/nonexistent", "usr/lib/dangling")

	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"/usr/lib/real.so", "/usr/lib/real.so", false},
		{"/lib/real.so", "/usr/lib/real.so", false},
		{"lib/real.so", "/usr/lib/real.so", false},
		{"/usr/lib/rel.so", "/usr/lib/real.so", false},
		{"/usr/lib/abs.so", "/usr/lib/real.so", false},
		{"/lib/abs.so", "/usr/lib/real.so", false},
		{"/usr/lib/sub/escape", "/etc", false},
		{"/usr/lib/sub/../real.so", "/usr/lib/real.so", false},
		{"/../../usr/lib/real.so", "/usr/lib/real.so", false},
		{"/", "/", false},
		{"/usr/lib/loop", "", true},
		{"/usr/lib/a", "", true},
		{"/usr/lib/dangling", "", true},
		{"/usr/lib/missing", "", true},
	}
	for _, tc := range tests {
		got, err := resolveInRoot(root, tc.in, 40)
		if (err != nil) != tc.wantErr {
			t.Errorf("resolveInRoot(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveInRoot(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := resolveInRoot(root, "/usr/lib/loop", 40); !errors.Is(err, errTooManyLinks) {
		t.Errorf("loop error = %v, want errTooManyLinks", err)
	}
	// The hop limit is honoured: a 3-link chain fails with maxHops=2.
	link(t, root, "real.so", "usr/lib/c3")
	link(t, root, "c3", "usr/lib/c2")
	link(t, root, "c2", "usr/lib/c1")
	if _, err := resolveInRoot(root, "/usr/lib/c1", 2); !errors.Is(err, errTooManyLinks) {
		t.Errorf("maxHops=2 error = %v", err)
	}
	if got, err := resolveInRoot(root, "/usr/lib/c1", 3); err != nil || got != "/usr/lib/real.so" {
		t.Errorf("maxHops=3 = %q, %v", got, err)
	}
}
