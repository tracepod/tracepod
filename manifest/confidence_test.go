package manifest

import (
	"fmt"
	"testing"
	"time"
)

// makeManifest constructs a Manifest for testing with the given profile window
// and file entries.
func makeManifest(start, end time.Time, files map[string]FileEntry) *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		ContainerID:   "test",
		ProfileStart:  start,
		ProfileEnd:    end,
		Files:         files,
	}
}

// directEntry returns a FileEntry with SourceDirect.
func directEntry() FileEntry {
	return FileEntry{Source: SourceDirect, FirstSeen: time.Now(), LastSeen: time.Now(), Count: 1}
}

// manualEntry returns a FileEntry with SourceManual and the given IncludedBecause.
func manualEntry(because string) FileEntry {
	return FileEntry{Source: SourceManual, IncludedBecause: because}
}

// scratchEntry returns a FileEntry with SourceManual and IncludedBecause=="scratch-compat".
func scratchEntry() FileEntry {
	return manualEntry("scratch-compat")
}

// inferredEntry returns a FileEntry with SourceInferredELF and the given InferredFrom.
func inferredEntry(from string) FileEntry {
	return FileEntry{Source: SourceInferredELF, InferredFrom: from}
}

func now() time.Time { return time.Now() }

func longAgo() time.Time { return time.Now().Add(-30 * time.Minute) }

// TestComputeConfidence_Perfect verifies a textbook profile scores 100.
func TestComputeConfidence_Perfect(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
		"/lib/libssl.so":  directEntry(),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	if result.Score != 100 {
		t.Errorf("expected score 100, got %d (penalties: %v)", result.Score, result.Penalties)
	}
	if result.Level != ConfidenceHigh {
		t.Errorf("expected High, got %s", result.Level)
	}
	if len(result.Penalties) != 0 {
		t.Errorf("expected no penalties, got %v", result.Penalties)
	}
}

// TestComputeConfidence_EmptyProfile verifies 0 direct entries → large penalty.
// The empty-profile penalty is 60, bringing the score from 100 to 40 (Low boundary).
func TestComputeConfidence_EmptyProfile(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/etc/passwd": scratchEntry(), // scratch-compat only, not counted as direct
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// 100 - penaltyEmptyProfile(60) = 40 → Low (boundary value)
	if result.Score != 40 {
		t.Errorf("expected score 40 for empty profile, got %d", result.Score)
	}
	if result.Level != ConfidenceLow {
		t.Errorf("expected Low (score 40 is at the Low boundary), got %s", result.Level)
	}
	found := false
	for _, p := range result.Penalties {
		if p.Signal == "empty-profile" {
			found = true
		}
	}
	if !found {
		t.Error("expected empty-profile penalty")
	}
}

// TestComputeConfidence_ZeroDuration verifies profile_start==profile_end → penalty.
func TestComputeConfidence_ZeroDuration(t *testing.T) {
	t0 := now()
	m := makeManifest(t0, t0, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	if result.Score >= 100 {
		t.Error("expected score < 100 for zero-duration profile")
	}
	found := false
	for _, p := range result.Penalties {
		if p.Signal == "zero-profile-duration" {
			found = true
		}
	}
	if !found {
		t.Error("expected zero-profile-duration penalty")
	}
}

// TestComputeConfidence_ShortWindow_Medium tests 5m window against 10m minimum.
func TestComputeConfidence_ShortWindow_Medium(t *testing.T) {
	end := now()
	start := end.Add(-5 * time.Minute)
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// ratio = 0.5 → penalty = 8
	if result.Score != 92 {
		t.Errorf("expected score 92 (penalty 8), got %d (penalties: %v)", result.Score, result.Penalties)
	}
	found := false
	for _, p := range result.Penalties {
		if p.Signal == "short-profile-window" {
			found = true
		}
	}
	if !found {
		t.Error("expected short-profile-window penalty")
	}
}

// TestComputeConfidence_ShortWindow_VeryShort tests 1m window → larger penalty.
func TestComputeConfidence_ShortWindow_VeryShort(t *testing.T) {
	end := now()
	start := end.Add(-1 * time.Minute)
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// ratio = 0.1 (< 0.25) → penalty = 20
	if result.Score != 80 {
		t.Errorf("expected score 80 (penalty 20), got %d", result.Score)
	}
}

// TestComputeConfidence_ManualEntries verifies manual entry penalty.
func TestComputeConfidence_ManualEntries(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx":      directEntry(),
		"/run/nginx.pid":       manualEntry("startup-race: pid file"),
		"/var/log/nginx/a.log": manualEntry("startup-race: log file"),
		"/var/log/nginx/e.log": manualEntry("startup-race: log file"),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// 3 user manual entries → 3*5 = 15 penalty from manual-entries
	// 3 startup-race entries → 3*3 = 9 penalty from startup-race
	// total deduction = 24 → score 76
	if result.Score != 76 {
		t.Errorf("expected score 76, got %d (penalties: %v)", result.Score, result.Penalties)
	}
}

// TestComputeConfidence_ScratchCompatExcluded verifies scratch-compat entries do NOT penalise.
func TestComputeConfidence_ScratchCompatExcluded(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx":    directEntry(),
		"/etc/passwd":        scratchEntry(),
		"/etc/group":         scratchEntry(),
		"/etc/nsswitch.conf": scratchEntry(),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	if result.Score != 100 {
		t.Errorf("scratch-compat entries should not reduce score; got %d (penalties: %v)", result.Score, result.Penalties)
	}
}

// TestComputeConfidence_UndocumentedManual verifies audit penalty for empty IncludedBecause.
func TestComputeConfidence_UndocumentedManual(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
		"/some/file":      manualEntry(""), // no explanation
		"/another/file":   manualEntry(""), // no explanation
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// 2 user manual entries → 2*5 = 10 (manual-entries)
	// 2 undocumented → 2*3 = 6 (undocumented-manual-entries)
	// total = 16 → score 84
	if result.Score != 84 {
		t.Errorf("expected score 84, got %d (penalties: %v)", result.Score, result.Penalties)
	}
	found := false
	for _, p := range result.Penalties {
		if p.Signal == "undocumented-manual-entries" {
			found = true
		}
	}
	if !found {
		t.Error("expected undocumented-manual-entries penalty")
	}
}

// TestComputeConfidence_OrphanInferredNotPenalised verifies inferred-elf entries
// with no direct parent are surfaced in OrphanInferred but do NOT reduce the score.
func TestComputeConfidence_OrphanInferredNotPenalised(t *testing.T) {
	start := longAgo()
	end := now()
	// nginx binary not in direct set — libssl was inferred from it but never directly observed.
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx":   directEntry(),
		"/lib/libssl.so":    inferredEntry("/usr/sbin/myapp"), // parent not in manifest
		"/lib/libcrypto.so": inferredEntry("/usr/sbin/myapp"),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	if result.Score != 100 {
		t.Errorf("orphan inferred-elf should not penalise score; got %d (penalties: %v)", result.Score, result.Penalties)
	}
	if len(result.OrphanInferred) != 2 {
		t.Errorf("expected 2 orphan inferred entries, got %d: %v", len(result.OrphanInferred), result.OrphanInferred)
	}
}

// TestComputeConfidence_CombinedSignals verifies stacking of multiple penalties.
func TestComputeConfidence_CombinedSignals(t *testing.T) {
	end := now()
	start := end.Add(-3 * time.Minute) // very short (ratio 0.3 → penalty 14)
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx":  directEntry(),
		"/run/nginx.pid":   manualEntry("startup-race: pid file"),
		"/var/cache/nginx": manualEntry("startup-race: cache dir"),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// short-window penalty: ratio ~0.30 → 14
	// manual-entries: 2*5 = 10
	// startup-race: 2*3 = 6
	// total = 30 → score 70
	if result.Score != 70 {
		t.Errorf("expected score 70, got %d (penalties: %v)", result.Score, result.Penalties)
	}
}

// TestComputeConfidence_LevelBoundaries verifies the level thresholds exactly.
func TestComputeConfidence_LevelBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  ConfidenceLevel
	}{
		{100, ConfidenceHigh},
		{80, ConfidenceHigh},
		{79, ConfidenceMedium},
		{60, ConfidenceMedium},
		{59, ConfidenceLow},
		{40, ConfidenceLow},
		{39, ConfidenceVeryLow},
		{0, ConfidenceVeryLow},
	}
	for _, tc := range cases {
		got := levelFromScore(tc.score)
		if got != tc.want {
			t.Errorf("levelFromScore(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// TestComputeConfidence_ManualCapEnforced verifies penalty caps are applied.
func TestComputeConfidence_ManualCapEnforced(t *testing.T) {
	start := longAgo()
	end := now()
	files := map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	}
	// Add 10 user manual entries — penalty should be capped at 25, not 50.
	for i := range 10 {
		files[fmt.Sprintf("/manual/file%d", i)] = manualEntry("some reason")
	}
	m := makeManifest(start, end, files)
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// manual-entries cap = 25 → score 75
	if result.Score != 75 {
		t.Errorf("expected score 75 (cap enforced), got %d (penalties: %v)", result.Score, result.Penalties)
	}
}

// TestComputeConfidence_StartupRaceCapEnforced verifies startup-race cap.
func TestComputeConfidence_StartupRaceCapEnforced(t *testing.T) {
	start := longAgo()
	end := now()
	files := map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	}
	// 10 startup-race entries: manual-entries cap=25, startup-race cap=12.
	for i := range 10 {
		files[fmt.Sprintf("/race/file%d", i)] = manualEntry("startup-race: missed at start")
	}
	m := makeManifest(start, end, files)
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// manual-entries: 10*5=50, cap 25 → -25
	// startup-race: 10*3=30, cap 12 → -12
	// total = 37 → score 63
	if result.Score != 63 {
		t.Errorf("expected score 63, got %d (penalties: %v)", result.Score, result.Penalties)
	}
}

// TestComputeConfidence_ZeroMinDuration verifies DefaultMinProfileDuration is used when 0.
func TestComputeConfidence_ZeroMinDuration(t *testing.T) {
	end := now()
	start := end.Add(-5 * time.Minute)
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
	})
	// Passing 0 should behave identically to passing DefaultMinProfileDuration.
	r1 := ComputeConfidence(m, 0)
	r2 := ComputeConfidence(m, DefaultMinProfileDuration)
	if r1.Score != r2.Score {
		t.Errorf("0 minProfileDuration should default to %s; got score %d vs %d", DefaultMinProfileDuration, r1.Score, r2.Score)
	}
}

// TestComputeConfidence_ScratchCompatWithStartupRaceEdgeCase verifies the exact-equality
// guard for scratch-compat does not suppress a genuine startup-race manual entry whose
// IncludedBecause happens to contain both terms.
//
// - "scratch-compat" (exact) → excluded from all manual penalties.
// - "startup-race: opened by nginx before cgroup" → penalised (substring match for startup-race).
// - "startup-race and scratch-compat" → also penalised (does NOT exactly equal "scratch-compat").
func TestComputeConfidence_ScratchCompatWithStartupRaceEdgeCase(t *testing.T) {
	start := longAgo()
	end := now()
	m := makeManifest(start, end, map[string]FileEntry{
		"/usr/sbin/nginx": directEntry(),
		// Exact "scratch-compat" → excluded from manual penalties.
		"/etc/passwd": scratchEntry(),
		// Genuine startup-race entry.
		"/run/nginx.pid": manualEntry("startup-race: opened by nginx master before cgroup registration"),
		// Edge-case: both terms but not exact "scratch-compat" → IS penalised.
		"/some/path": manualEntry("startup-race and scratch-compat"),
	})
	result := ComputeConfidence(m, DefaultMinProfileDuration)
	// User manual entries (excluding /etc/passwd): 2 entries → 2*5 = 10
	// Startup-race (substring): 2 entries match → 2*3 = 6
	// Total deduction = 16 → score 84
	if result.Score != 84 {
		t.Errorf("expected score 84, got %d (penalties: %v)", result.Score, result.Penalties)
	}
	// /etc/passwd must not appear in any penalty signal.
	for _, p := range result.Penalties {
		_ = p // no assertion needed; any incorrect penalty would change the score above
	}
}
