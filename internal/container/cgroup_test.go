package container_test

import (
	"errors"
	"os"
	"testing"

	"github.com/tracepod/tracepod/internal/container"
)

func TestCgroupIDFromPath_existingAbsoluteDir(t *testing.T) {
	// /tmp always exists; stat succeeds without root and returns a non-zero inode.
	id, err := container.CgroupIDFromPath("/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == 0 {
		t.Error("cgroup ID must be non-zero")
	}
}

func TestCgroupIDFromPath_missingPathReturnsError(t *testing.T) {
	_, err := container.CgroupIDFromPath("/tmp/no-such-dir-for-neeva-test")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}
