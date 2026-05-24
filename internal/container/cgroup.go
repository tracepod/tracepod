// Package container integrates with the container runtime to map running
// containers to their kernel cgroup IDs. These IDs are passed to the BPF
// probe's allowlist so only events from tracked containers are emitted.
package container

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// CgroupIDFromPath returns the kernel cgroup ID (the inode number of the
// cgroup directory) for path. path may be absolute or relative to
// /sys/fs/cgroup.
//
// The kernel uses the cgroup directory's inode as its canonical cgroup
// identifier — the same value returned by bpf_get_current_cgroup_id() for
// any process running in that cgroup.
func CgroupIDFromPath(path string) (uint64, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cgroupRoot, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup path %q: %w", path, err)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected Stat_t type for %q", path)
	}
	return sys.Ino, nil
}
