package candidates

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tracepod/tracepod/hardener"
)

func f(p string) Entry    { return Entry{Path: p, Type: "file"} }
func d(p string) Entry    { return Entry{Path: p, Type: "dir"} }
func kept(p string) Entry { return Entry{Path: p, Type: "file", InHardened: true} }

func paths(cs []Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Path)
	}
	return out
}

func TestGenerateTable(t *testing.T) {
	sym := Entry{Path: "/usr/lib/libfoo.so.1", Type: "symlink", LinkTarget: "libfoo.so.1.2.3"}
	tests := []struct {
		name    string
		entries []Entry
		logs    string
		want    []string // expected leading paths, in order
		match   map[string]string
	}{
		{
			name: "python ModuleNotFoundError",
			entries: []Entry{
				d("/usr/lib/python3.12/site-packages/yaml"),
				f("/usr/lib/python3.12/site-packages/yaml/__init__.py"),
				f("/usr/lib/python3.12/site-packages/yaml/constructor.py"),
				f("/usr/lib/python3.12/site-packages/requests/api.py"),
				kept("/usr/lib/python3.12/site-packages/yaml/loader.py"),
			},
			logs:  "Traceback (most recent call last):\n  File \"/app/main.py\", line 1, in <module>\nModuleNotFoundError: No module named 'yaml.constructor'\n",
			want:  []string{"/usr/lib/python3.12/site-packages/yaml/constructor.py"},
			match: map[string]string{"/usr/lib/python3.12/site-packages/yaml/constructor.py": MatchSegment},
		},
		{
			name:    "node Cannot find module",
			entries: []Entry{d("/app/node_modules/left-pad"), f("/app/node_modules/left-pad/index.js"), f("/app/other.js")},
			logs:    "Error: Cannot find module 'left-pad'\nRequire stack:\n- /app/index.js",
			want:    []string{"/app/node_modules/left-pad"},
			match:   map[string]string{"/app/node_modules/left-pad": MatchBasename},
		},
		{
			name:    "java ClassNotFoundException",
			entries: []Entry{f("/app/lib/com/acme/Widget.class"), f("/app/lib/com/acme/Other.class")},
			logs:    "Exception in thread \"main\" java.lang.ClassNotFoundException: com.acme.Widget",
			want:    []string{"/app/lib/com/acme/Widget.class"},
			match:   map[string]string{"/app/lib/com/acme/Widget.class": MatchSegment},
		},
		{
			name:    "shared object with symlink chain",
			entries: []Entry{sym, f("/usr/lib/libfoo.so.1.2.3"), f("/usr/lib/libbar.so.2")},
			logs:    "./server: error while loading shared libraries: libfoo.so.1: cannot open shared object file: No such file or directory",
			want:    []string{"/usr/lib/libfoo.so.1", "/usr/lib/libfoo.so.1.2.3"},
			match:   map[string]string{"/usr/lib/libfoo.so.1": MatchBasename},
		},
		{
			name:    "nginx quoted path",
			entries: []Entry{f("/etc/nginx/mime.types"), f("/etc/nginx/nginx.conf")},
			logs:    `nginx: [emerg] open() "/etc/nginx/mime.types" failed (2: No such file or directory) in /etc/nginx/nginx.conf:12`,
			want:    []string{"/etc/nginx/mime.types"},
			match:   map[string]string{"/etc/nginx/mime.types": MatchQuoted},
		},
		{
			name:    "quoted path elsewhere in image matches by basename",
			entries: []Entry{f("/usr/share/nginx/mime.types")},
			logs:    `open() "/etc/nginx/mime.types" failed (2: No such file or directory)`,
			want:    []string{"/usr/share/nginx/mime.types"},
			match:   map[string]string{"/usr/share/nginx/mime.types": MatchBasename},
		},
		{
			name:    "zoneinfo",
			entries: []Entry{f("/usr/share/zoneinfo/UTC"), f("/usr/share/zoneinfo/Europe/London"), kept("/usr/share/zoneinfo/GMT")},
			logs:    `panic: unknown time zone: open '/usr/share/zoneinfo/Europe/London': no such file or directory`,
			want:    []string{"/usr/share/zoneinfo/Europe/London"},
			match:   map[string]string{"/usr/share/zoneinfo/Europe/London": MatchQuoted},
		},
		{
			name:    "stem match",
			entries: []Entry{f("/opt/app/settings.yaml")},
			logs:    "ConfigError: failed to read settings",
			want:    []string{"/opt/app/settings.yaml"},
			match:   map[string]string{"/opt/app/settings.yaml": MatchStem},
		},
		{
			name:    "environmental noise only",
			entries: []Entry{f("/usr/bin/curl"), f("/etc/hostname")},
			logs:    "dial tcp 10.0.0.5:5432: connect: connection refused\nAccessDenied: not authorized\nlookup db.internal: no such host\nrequest failed with timeout",
			want:    nil,
		},
		{
			name:    "noise plus a real file token",
			entries: []Entry{f("/etc/ssl/certs/ca-bundle.crt")},
			logs:    "x509: failed to load system roots: open /etc/ssl/certs/ca-bundle.crt: connection refused",
			want:    []string{"/etc/ssl/certs/ca-bundle.crt"},
		},
		{
			name:    "kept in hardened image is never a candidate",
			entries: []Entry{kept("/etc/nginx/mime.types")},
			logs:    `open() "/etc/nginx/mime.types" failed`,
			want:    nil,
		},
		{
			name:    "proc sys dev excluded",
			entries: []Entry{f("/proc/self/maps"), f("/sys/kernel/foo"), f("/dev/null")},
			logs:    `error: cannot open "/proc/self/maps" "/sys/kernel/foo" "/dev/null"`,
			want:    nil,
		},
		{
			name:    "non-error lines ignored",
			entries: []Entry{f("/etc/secret.conf")},
			logs:    "starting up using /etc/secret.conf\nlistening",
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Generate(tt.entries, tt.logs, Options{})
			gp := paths(got)
			if len(tt.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("want no candidates, got %v", gp)
				}
				return
			}
			if len(gp) < len(tt.want) || !reflect.DeepEqual(gp[:len(tt.want)], tt.want) {
				t.Fatalf("got %v, want prefix %v", gp, tt.want)
			}
			for _, c := range got {
				if want, ok := tt.match[c.Path]; ok && c.Match != want {
					t.Errorf("%s: match %q, want %q", c.Path, c.Match, want)
				}
				if c.Evidence == "" {
					t.Errorf("%s: empty evidence", c.Path)
				}
			}
		})
	}
}

func TestScoresAndSymlinkTarget(t *testing.T) {
	got := Generate([]Entry{
		{Path: "/usr/lib/libfoo.so.1", Type: "symlink", LinkTarget: "libfoo.so.1.2.3"},
		f("/usr/lib/libfoo.so.1.2.3"),
	}, "error: libfoo.so.1: cannot open shared object file", Options{})
	if len(got) != 2 || got[0].Score != 80 || got[1].Score != 79 || got[1].Path != "/usr/lib/libfoo.so.1.2.3" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestSymlinkTargetOutsideUniverseNotAdded(t *testing.T) {
	got := Generate([]Entry{
		{Path: "/usr/lib/libfoo.so.1", Type: "symlink", LinkTarget: "/lib/missing.so"},
		kept("/lib/missing.so"),
	}, "error: libfoo.so.1 not found", Options{})
	if p := paths(got); len(p) != 1 || p[0] != "/usr/lib/libfoo.so.1" {
		t.Fatalf("got %v", p)
	}
}

func TestSymlinkCycleTerminates(t *testing.T) {
	got := Generate([]Entry{
		{Path: "/a/libx.so", Type: "symlink", LinkTarget: "/a/b"},
		{Path: "/a/b", Type: "symlink", LinkTarget: "/a/libx.so"},
	}, "error: libx.so missing", Options{})
	if len(got) == 0 {
		t.Fatal("expected candidates")
	}
}

func TestMaxAndSorting(t *testing.T) {
	var es []Entry
	for _, n := range []string{"c", "a", "b", "d"} {
		es = append(es, f("/x/"+n+"/target.so"))
	}
	got := Generate(es, "error loading target.so", Options{Max: 3})
	want := []string{"/x/a/target.so", "/x/b/target.so", "/x/c/target.so"}
	if !reflect.DeepEqual(paths(got), want) {
		t.Fatalf("got %v want %v", paths(got), want)
	}
}

func TestDeterministic(t *testing.T) {
	var es []Entry
	for i := 0; i < 50; i++ {
		es = append(es, f("/lib/mod"+string(rune('a'+i%26))+"/x"+string(rune('a'+i/26))+".py"))
	}
	logs := "ModuleNotFoundError: No module named 'moda.xa'\nerror: cannot find xb"
	first := Generate(es, logs, Options{})
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(first, Generate(es, logs, Options{})) {
			t.Fatal("non-deterministic output")
		}
	}
}

func TestNeverInventsPaths(t *testing.T) {
	es := []Entry{f("/a/b.so"), kept("/c/d.so"), f("/e/f.so")}
	universe := map[string]bool{"/a/b.so": true, "/e/f.so": true}
	for _, c := range Generate(es, `error "/zzz/q.so" b.so f.so d.so /nope/ghost`, Options{}) {
		if !universe[c.Path] {
			t.Errorf("invented or excluded path %s", c.Path)
		}
	}
}

func TestEmptyUniverse(t *testing.T) {
	if Generate(nil, "error foo", Options{}) != nil {
		t.Fatal("want nil")
	}
	if Generate([]Entry{kept("/a")}, "error a", Options{}) != nil {
		t.Fatal("want nil")
	}
}

func TestEvidenceTruncated(t *testing.T) {
	got := Generate([]Entry{f("/a/target.so")}, "error "+strings.Repeat("x", 1000)+" target.so", Options{})
	if len(got) != 1 || len(got[0].Evidence) > maxEvidenceLen {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestLoadInventory(t *testing.T) {
	es, err := LoadInventory(strings.NewReader(`{"version":1,"files":[{"path":"/a","type":"file","in_hardened":false},{"path":"/l","type":"symlink","link_target":"a","in_hardened":true}]}`))
	if err != nil || len(es) != 2 || es[1].LinkTarget != "a" || !es[1].InHardened {
		t.Fatalf("got %+v, %v", es, err)
	}
	for _, bad := range []string{`{"version":2,"files":[]}`, `{"files":[]}`, `not json`} {
		if _, err := LoadInventory(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

// The on-disk document written by the hardener must load unchanged.
func TestLoadsHardenerInventory(t *testing.T) {
	doc := hardener.InventoryFile{
		Version: hardener.InventoryVersion,
		Files: []hardener.InventoryEntry{
			{Path: "/usr/lib/libz.so.1", Type: hardener.InventoryTypeSymlink, LinkTarget: "libz.so.1.3", InHardened: false},
			{Path: "/usr/lib/libz.so.1.3", Type: hardener.InventoryTypeFile},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	es, err := LoadInventory(strings.NewReader(string(b)))
	if err != nil || len(es) != 2 || es[0].LinkTarget != "libz.so.1.3" {
		t.Fatalf("got %+v, %v", es, err)
	}
}
