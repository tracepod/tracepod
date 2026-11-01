//go:build linux

package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

const (
	// minSnapshotInterval is the smallest non-zero --snapshot-interval.
	minSnapshotInterval = 10 * time.Second
	// snapshotFailLogEvery rate-limits interim POST failure logs per container.
	snapshotFailLogEvery = 10 * time.Minute
)

// validateSnapshotInterval enforces: 0 (off) or >= minSnapshotInterval.
func validateSnapshotInterval(d time.Duration) error {
	if d != 0 && d < minSnapshotInterval {
		return fmt.Errorf("--snapshot-interval must be 0 or >= %s (got %s)", minSnapshotInterval, d)
	}
	return nil
}

// snapshotJitter returns a deterministic offset in [0, interval) derived from
// the container ID, so containers' first snapshots spread across the interval
// instead of all firing together.
func snapshotJitter(containerID string, interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	// 64-bit hash: a 32-bit one tops out near 4.3s in nanoseconds and would
	// bunch every offset into the start of any longer interval.
	h := fnv.New64a()
	_, _ = h.Write([]byte(containerID))
	return time.Duration(h.Sum64() % uint64(interval))
}

// snapshotTickEvery is how often the loop wakes to look for due containers.
func snapshotTickEvery(interval time.Duration) time.Duration {
	t := interval / 10
	if t < time.Second {
		t = time.Second
	}
	return t
}

func (r *cgroupRouter) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// startSnapshots launches the interim snapshot loop on a real ticker and
// returns a stop function that cancels it and waits for it to exit (including
// any in-flight POST, which the cancellation aborts). Call stop before
// flushAll. It is a no-op returning a no-op stop when snapshotInterval is 0.
func (r *cgroupRouter) startSnapshots() (stop func()) {
	if r.snapshotInterval <= 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(snapshotTickEvery(r.snapshotInterval))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		r.runSnapshots(ctx, ticker.C)
	}()
	return func() {
		cancel()
		<-done
	}
}

// runSnapshots runs one snapshot pass per value received on tick until ctx is
// cancelled. The tick source is injected so tests can drive it.
func (r *cgroupRouter) runSnapshots(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			r.snapshotPass(ctx)
		}
	}
}

type snapshotCandidate struct {
	agg    *manifest.Aggregator
	target *postTarget
	dep    string
	image  string
}

// snapshotPass POSTs an interim snapshot for every tracked container that is
// due. Only targets whose owning workload was already resolved are posted: the
// periodic path never performs a live lookup and never uses the bare-pod
// fallback; those containers are reported at stop as usual. Failures are logged
// (rate-limited) and simply retried at the next scheduled time — snapshots are
// cumulative, so a later one supersedes a lost one.
func (r *cgroupRouter) snapshotPass(ctx context.Context) {
	now := r.clock()

	r.mu.Lock()
	var due []snapshotCandidate
	for cg, agg := range r.aggs {
		t := r.targets[cg]
		if t == nil || !t.resolved || t.deployment == "" || t.pod.Namespace == "" {
			continue
		}
		if now.Before(t.nextSnapshotAt) {
			continue
		}
		// Advance the schedule now, whatever the outcome; never burst to catch up.
		next := t.nextSnapshotAt.Add(r.snapshotInterval)
		if !next.After(now) {
			next = now.Add(r.snapshotInterval)
		}
		t.nextSnapshotAt = next
		due = append(due, snapshotCandidate{agg, t, t.deployment, t.imageRef})
	}
	r.mu.Unlock()

	for _, c := range due {
		if ctx.Err() != nil {
			return
		}
		r.postInterim(ctx, c, now)
	}
}

func (r *cgroupRouter) postInterim(ctx context.Context, c snapshotCandidate, now time.Time) {
	t := c.target
	t.postMu.Lock()
	defer t.postMu.Unlock()
	if t.closed {
		return // stopped or flushed since we collected it
	}
	if c.image != "" {
		c.agg.SetImageRef(c.image)
	}
	snap := c.agg.Snapshot()
	if err := r.postSnapshot(ctx, t, c.dep, c.image, snap); err != nil {
		r.mu.Lock()
		log := now.Sub(t.lastFailLog) >= snapshotFailLogEvery || t.lastFailLog.IsZero()
		if log {
			t.lastFailLog = now
		}
		r.mu.Unlock()
		if log {
			fmt.Fprintf(os.Stderr, "sensor: interim snapshot POST failed for %s/%s (container=%s): %v\n",
				t.pod.Namespace, c.dep, t.containerID, err)
		}
	}
}
