package sensor

import "testing"

func TestNamespaceScope_Allows(t *testing.T) {
	cases := []struct {
		name             string
		include, exclude string
		ns               string
		want             bool
	}{
		{"default allows everything", "", "", "kube-system", true},
		{"default allows unknown namespace", "", "", "", true},
		{"include exact match", "shop,payments", "", "payments", true},
		{"include no match", "shop,payments", "", "kube-system", false},
		{"include glob", "team-*", "", "team-a", true},
		{"include glob no match", "team-*", "", "teams", false},
		{"exclude exact", "", "kube-system", "kube-system", false},
		{"exclude leaves others", "", "kube-system", "default", true},
		{"exclude glob", "", "kube-*", "kube-node-lease", false},
		{"exclude wins over include", "team-*", "team-b", "team-b", false},
		{"exclude wins over same include", "shop", "shop", "shop", false},
		{"unknown namespace out when include set", "shop", "", "", false},
		{"unknown namespace in when only exclude set", "", "kube-system", "", true},
		{"spaces and empty entries ignored", " shop , ,payments ", "", "payments", true},
		{"no substring match", "shop", "", "shopping", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewNamespaceScope(tc.include, tc.exclude)
			if err != nil {
				t.Fatalf("NewNamespaceScope: %v", err)
			}
			if got := s.Allows(tc.ns); got != tc.want {
				t.Errorf("Allows(%q) = %t, want %t (include=%q exclude=%q)", tc.ns, got, tc.want, tc.include, tc.exclude)
			}
		})
	}
}

func TestNamespaceScope_NilAllowsEverything(t *testing.T) {
	var s *NamespaceScope
	if !s.Allows("kube-system") || !s.Allows("") || !s.IsAll() {
		t.Fatal("nil scope must allow every namespace")
	}
	if got := s.String(); got != "all namespaces" {
		t.Errorf("String() = %q", got)
	}
}

func TestNamespaceScope_BadPattern(t *testing.T) {
	if _, err := NewNamespaceScope("team-[", ""); err == nil {
		t.Error("expected an error for a malformed include pattern")
	}
	if _, err := NewNamespaceScope("", "["); err == nil {
		t.Error("expected an error for a malformed exclude pattern")
	}
}

func TestNamespaceScope_String(t *testing.T) {
	cases := []struct{ include, exclude, want string }{
		{"", "", "all namespaces"},
		{"shop,team-*", "", "include=shop,team-* exclude=none"},
		{"", "kube-system", "include=all exclude=kube-system"},
		{"shop", "shop-test", "include=shop exclude=shop-test"},
	}
	for _, tc := range cases {
		s, err := NewNamespaceScope(tc.include, tc.exclude)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.String(); got != tc.want {
			t.Errorf("String(%q,%q) = %q, want %q", tc.include, tc.exclude, got, tc.want)
		}
	}
}
