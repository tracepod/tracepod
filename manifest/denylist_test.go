package manifest_test

import (
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

func TestDefaultDenyList_blocksNoisePatterns(t *testing.T) {
	d := manifest.DefaultDenyList()

	denied := []string{
		"/proc/1/maps",
		"/proc/self/fd/0",
		"/proc/12345/status",
		"/sys/fs/cgroup/memory/usage",
		"/sys/kernel/debug/tracing/events",
		"/dev/null",
		"/dev/urandom",
		"/run/containerd/io.containerd.runtime.v2.task/default/abc/rootfs",
		"/run/secrets/mytoken",
		"/var/run/nginx.pid",
		"/var/run/docker.sock",
		"/tmp/tmpfile123",
		"/tmp/subdir/file.tmp",
		"/var/log/nginx/access.log",
		"/app/logs/app.log",
		"/app/debug.log.1",
	}

	for _, path := range denied {
		if d.Allow(path) {
			t.Errorf("Allow(%q) = true, want false (should be denied)", path)
		}
	}
}

func TestDefaultDenyList_allowsLegitPaths(t *testing.T) {
	d := manifest.DefaultDenyList()

	allowed := []string{
		"/usr/sbin/nginx",
		"/etc/nginx/nginx.conf",
		"/etc/ssl/certs/ca-certificates.crt",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/python3.12/os.py",
		"/app/server",
		"/var/lib/redis/dump.rdb",
		"/etc/passwd",
		"/usr/share/zoneinfo/UTC",
	}

	for _, path := range allowed {
		if !d.Allow(path) {
			t.Errorf("Allow(%q) = false, want true (should be allowed)", path)
		}
	}
}

func TestDenyList_Add_customPattern(t *testing.T) {
	d := manifest.DefaultDenyList()
	d.Add("/var/cache/")

	if d.Allow("/var/cache/apt/pkgcache.bin") {
		t.Error("Allow(/var/cache/apt/pkgcache.bin) = true, want false after adding /var/cache/")
	}
	// Non-matching path should still be allowed
	if !d.Allow("/var/lib/redis/dump.rdb") {
		t.Error("Allow(/var/lib/redis/dump.rdb) = false, want true")
	}
}

func TestNewDenyList_emptyAllowsEverything(t *testing.T) {
	d := manifest.NewDenyList()

	paths := []string{"/proc/1/maps", "/sys/fs/cgroup", "/tmp/foo", "/etc/passwd"}
	for _, p := range paths {
		if !d.Allow(p) {
			t.Errorf("empty DenyList: Allow(%q) = false, want true", p)
		}
	}
}

func TestDenyList_Add_multiplePatterns(t *testing.T) {
	d := manifest.NewDenyList()
	d.Add("/a/*", "/b/*", "/c/*")

	for _, denied := range []string{"/a/foo", "/b/bar", "/c/baz"} {
		if d.Allow(denied) {
			t.Errorf("Allow(%q) = true, want false", denied)
		}
	}
	if !d.Allow("/d/qux") {
		t.Error("Allow(/d/qux) = false, want true")
	}
}
