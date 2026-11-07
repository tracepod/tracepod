package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// Local smoke test: the laptop-scale version of the controller's sandbox
// validation. The freshly built OCI layout is loaded into the local Docker
// daemon and run for a grace window; an image that exits non-zero inside it
// fails the build the same way a crashing sandbox pod would in-cluster.
// It is a boot check, not a health check — it proves the minimized image can
// start its entrypoint, which is where broken minimization dies.

// smokeLogFilename is the container log saved in the output directory when the
// smoke test fails; `harden diagnose --log` reads it.
const smokeLogFilename = "smoke.log"

// smokeLogMaxBytes caps the saved log; the tail is kept.
const smokeLogMaxBytes = 200 * 1024

// runSmokeTest loads ociDir into the local Docker daemon under tag and runs
// it detached for graceWindow. Returns nil when the container is still
// running (or exited 0) at the end of the window. On failure the container log
// is written to logPath (when non-empty) before returning.
func runSmokeTest(ctx context.Context, ociDir, tag string, graceWindow time.Duration, logPath string) error {
	// A log from an earlier failed run in the same directory is stale.
	if logPath != "" {
		_ = os.Remove(logPath)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH (required for --smoke-test): %w", err)
	}

	lp, err := layout.FromPath(ociDir)
	if err != nil {
		return fmt.Errorf("open OCI layout: %w", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		return fmt.Errorf("load image index: %w", err)
	}
	mf, err := idx.IndexManifest()
	if err != nil || len(mf.Manifests) == 0 {
		return fmt.Errorf("OCI layout contains no images")
	}
	img, err := idx.Image(mf.Manifests[0].Digest)
	if err != nil {
		return fmt.Errorf("load image: %w", err)
	}
	ref, err := name.NewTag(tag)
	if err != nil {
		return fmt.Errorf("parse tag %q: %w", tag, err)
	}
	if _, err := daemon.Write(ref, img, daemon.WithContext(ctx)); err != nil {
		return fmt.Errorf("load image into docker daemon: %w", err)
	}

	ctr := "tracepod-smoke-" + fmt.Sprintf("%d", time.Now().UnixNano())
	defer exec.Command("docker", "rm", "-f", ctr).Run() //nolint:errcheck

	if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", ctr, tag).CombinedOutput(); err != nil {
		// The runtime's error (for example a missing entrypoint) is the log.
		saveSmokeLog(logPath, out)
		return fmt.Errorf("docker run: %v: %s", err, strings.TrimSpace(string(out)))
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(graceWindow):
	}

	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f",
		"{{.State.Running}} {{.State.ExitCode}}", ctr).Output()
	if err != nil {
		return fmt.Errorf("docker inspect: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 2 {
		return fmt.Errorf("unexpected docker inspect output: %q", out)
	}
	running, exitCode := fields[0] == "true", fields[1]
	if running || exitCode == "0" {
		return nil
	}
	logs, _ := exec.CommandContext(ctx, "docker", "logs", ctr).CombinedOutput()
	saveSmokeLog(logPath, logs)
	return fmt.Errorf("container exited %s within %s — the minimized image cannot boot.\nLast logs:\n%s",
		exitCode, graceWindow, lastLines(strings.TrimSpace(string(logs)), 40))
}

// saveSmokeLog writes the tail of logs to logPath; a failure only warns.
func saveSmokeLog(logPath string, logs []byte) {
	if logPath == "" {
		return
	}
	if len(logs) > smokeLogMaxBytes {
		logs = logs[len(logs)-smokeLogMaxBytes:]
	}
	if err := os.WriteFile(logPath, logs, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: save smoke-test log: %v\n", err)
	}
}

// lastLines returns the last n lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
