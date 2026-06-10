package manifest_test

import (
	"testing"
	"time"

	"github.com/tracepod/tracepod/manifest"
)

// TestProcessStartObserved_syntheticOrderings asserts the R2 marker across
// synthetic orderings of attach vs first-exec, including the uncertainty-toward-
// false rule. The marker may be true ONLY when the sensor recorded an attach,
// no process was already running at attach, an exec was observed, AND the attach
// strictly precedes that first exec.
func TestProcessStartObserved_syntheticOrderings(t *testing.T) {
	t0 := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	before := t0
	after := t0.Add(time.Second)

	type step struct {
		attach         *time.Time // nil → no RecordAttach call
		alreadyRunning bool
		execAt         *time.Time // nil → no exec observed
	}
	tp := func(x time.Time) *time.Time { return &x }

	cases := []struct {
		name string
		step step
		want bool
	}{
		{
			name: "attach before first exec, cgroup empty → true",
			step: step{attach: tp(before), alreadyRunning: false, execAt: tp(after)},
			want: true,
		},
		{
			name: "no attach recorded → false (toward-false)",
			step: step{attach: nil, alreadyRunning: false, execAt: tp(after)},
			want: false,
		},
		{
			name: "process already running at attach → false (race lost)",
			step: step{attach: tp(before), alreadyRunning: true, execAt: tp(after)},
			want: false,
		},
		{
			name: "no exec observed → false (nothing anchors first exec)",
			step: step{attach: tp(before), alreadyRunning: false, execAt: nil},
			want: false,
		},
		{
			name: "attach equals first exec → false (not strictly before)",
			step: step{attach: tp(t0), alreadyRunning: false, execAt: tp(t0)},
			want: false,
		},
		{
			name: "attach after first exec → false (toward-false)",
			step: step{attach: tp(after), alreadyRunning: false, execAt: tp(before)},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := manifest.NewAggregator("ctr", "")
			// Record the exec first so its timestamp is exactly execAt regardless
			// of attach ordering (RecordFile stamps firstExecTime from the arg).
			if tc.step.execAt != nil {
				a.RecordFile("/bin/app", manifest.SourceDirect,
					[]manifest.AccessMode{manifest.AccessExecute}, *tc.step.execAt)
			}
			if tc.step.attach != nil {
				a.RecordAttach(*tc.step.attach, tc.step.alreadyRunning)
			}
			got := a.Snapshot().Coverage.ProcessStartObserved
			if got != tc.want {
				t.Errorf("ProcessStartObserved = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCoverage_recordsAttachAndFirstExecTimes confirms the raw signals the
// consumer needs are surfaced alongside the boolean.
func TestCoverage_recordsAttachAndFirstExecTimes(t *testing.T) {
	attach := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	exec := attach.Add(2 * time.Second)

	a := manifest.NewAggregator("ctr", "")
	a.RecordAttach(attach, false)
	a.RecordFile("/bin/app", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessExecute}, exec)
	// A later exec must not move first_exec_time.
	a.RecordFile("/bin/other", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessExecute}, exec.Add(time.Minute))

	cov := a.Snapshot().Coverage
	if !cov.AttachTime.Equal(attach) {
		t.Errorf("AttachTime = %v, want %v", cov.AttachTime, attach)
	}
	if cov.FirstExecTime == nil || !cov.FirstExecTime.Equal(exec) {
		t.Errorf("FirstExecTime = %v, want %v", cov.FirstExecTime, exec)
	}
}

// TestCoverage_noExec_firstExecTimeNil confirms first_exec_time is omitted when
// no exec was observed.
func TestCoverage_noExec_firstExecTimeNil(t *testing.T) {
	a := manifest.NewAggregator("ctr", "")
	a.RecordAttach(time.Now(), false)
	a.RecordFile("/etc/conf", manifest.SourceDirect, []manifest.AccessMode{manifest.AccessRead}, time.Now())
	if fe := a.Snapshot().Coverage.FirstExecTime; fe != nil {
		t.Errorf("FirstExecTime = %v, want nil (no exec observed)", fe)
	}
}

// TestContainerStarts_recordedInOrder asserts the R3 start records: the
// constructor seeds the first start and RecordStart appends subsequent restarts,
// so a consumer can count full restarts as len(container_starts)-1.
func TestContainerStarts_recordedInOrder(t *testing.T) {
	t0 := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	a := manifest.NewAggregator("ctr-1", "")
	a.RecordStart("ctr-2", t0.Add(time.Minute))
	a.RecordStart("ctr-3", t0.Add(2*time.Minute))

	starts := a.Snapshot().ContainerStarts
	if len(starts) != 3 {
		t.Fatalf("len(container_starts) = %d, want 3", len(starts))
	}
	wantIDs := []string{"ctr-1", "ctr-2", "ctr-3"}
	for i, want := range wantIDs {
		if starts[i].ContainerID != want {
			t.Errorf("starts[%d].ContainerID = %q, want %q", i, starts[i].ContainerID, want)
		}
	}
	if starts[1].Timestamp != t0.Add(time.Minute).UTC() {
		t.Errorf("starts[1].Timestamp = %v, want %v", starts[1].Timestamp, t0.Add(time.Minute).UTC())
	}
	// restarts = len-1
	if restarts := len(starts) - 1; restarts != 2 {
		t.Errorf("computed restarts = %d, want 2", restarts)
	}
}

// TestContainerStarts_freshAggregatorHasOneStart confirms a single-start profile
// reports exactly one start (zero restarts) — the common case.
func TestContainerStarts_freshAggregatorHasOneStart(t *testing.T) {
	a := manifest.NewAggregator("only", "")
	if got := len(a.Snapshot().ContainerStarts); got != 1 {
		t.Errorf("len(container_starts) = %d, want 1", got)
	}
}
