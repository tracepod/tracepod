// Package manifest — confidence.go computes a coverage confidence score for a
// Manifest. The score quantifies how representative the profiling window was,
// based on signals derived purely from the manifest (no network calls, no image
// inspection).
//
// NOTE: The penalty weights below are v1 defaults calibrated against the
// nginx:1.25-alpine reference profile. They will be adjusted once real-world
// profiling data is available. Only minProfileDuration is user-tunable via the
// CLI; the internal constants are not part of the public API and may change in
// any patch release before GA. Do not hard-code specific score thresholds in
// external workflows until after the GA release.
package manifest

import (
	"fmt"
	"strings"
	"time"
)

// v1 penalty constants — see package-level NOTE before modifying.
const (
	penaltyEmptyProfile        = 60 // 0 direct entries → catastrophic signal
	penaltyZeroDuration        = 20 // profile_start == profile_end → likely bad data
	penaltyManualPerEntry      = 5  // per user manual entry (scratch-compat excluded)
	penaltyManualCap           = 25 // ceiling for manual-entry signal
	penaltyStartupRacePerEntry = 3  // per "startup-race" entry (stacks with manual)
	penaltyStartupRaceCap      = 12
	penaltyUndocPerEntry       = 3 // per undocumented manual entry (empty IncludedBecause)
	penaltyUndocCap            = 9
)

// DefaultMinProfileDuration is the recommended minimum profiling window.
// Profiles shorter than this receive a short-window penalty.
const DefaultMinProfileDuration = 10 * time.Minute

// ConfidenceLevel is a qualitative band for the confidence score.
type ConfidenceLevel string

const (
	ConfidenceHigh    ConfidenceLevel = "High"
	ConfidenceMedium  ConfidenceLevel = "Medium"
	ConfidenceLow     ConfidenceLevel = "Low"
	ConfidenceVeryLow ConfidenceLevel = "Very Low"
)

// ConfidencePenalty records a single signal that reduced the confidence score.
type ConfidencePenalty struct {
	// Signal is the machine-readable key (e.g. "startup-race", "short-profile-window").
	Signal string
	// Reason is a human-readable one-sentence explanation of what triggered this penalty.
	Reason string
	// Points is the number of points deducted (always negative or zero).
	Points int
}

// ConfidenceResult is the output of ComputeConfidence.
type ConfidenceResult struct {
	// Score is 0–100. 100 means all known gaps were mitigated during profiling.
	Score int
	// Level is the qualitative band derived from Score.
	Level ConfidenceLevel
	// Penalties lists every signal that reduced the score, in application order.
	Penalties []ConfidencePenalty
	// OrphanInferred lists inferred-elf paths whose InferredFrom binary has no
	// direct entry in the manifest. This is a correct and expected outcome of the
	// ELF resolver (the dynamic linker opens the library, not the application) and
	// is NOT penalised. It is surfaced here for --verbose audit output only.
	OrphanInferred []string
}

// ComputeConfidence scores m against the confidence signal table. If
// minProfileDuration is zero, DefaultMinProfileDuration is used.
//
// The confidence score is a coverage signal, not a quality grade. A score of
// 100 means all known sensor coverage gaps were actively mitigated during the
// profiling session. Lower scores identify which gaps remain open and what
// would close them. See CONFIDENCE.md for the full scoring reference.
func ComputeConfidence(m *Manifest, minProfileDuration time.Duration) ConfidenceResult {
	if minProfileDuration == 0 {
		minProfileDuration = DefaultMinProfileDuration
	}

	score := 100
	var penalties []ConfidencePenalty

	// Pass 1: classify entries and build index of direct paths.
	var directCount int
	directPaths := make(map[string]bool, len(m.Files))
	var userManual []FileEntry // manual entries excluding scratch-compat

	for path, e := range m.Files {
		switch e.Source {
		case SourceDirect:
			directCount++
			directPaths[path] = true
		case SourceManual:
			// scratch-compat entries are added by the hardener itself (not the user)
			// and must not count against the confidence score.
			if e.IncludedBecause != "scratch-compat" {
				userManual = append(userManual, e)
			}
		}
	}

	// Pass 2: identify orphan inferred-elf entries (for verbose audit; not penalised).
	var orphanInferred []string
	for path, e := range m.Files {
		if e.Source == SourceInferredELF && e.InferredFrom != "" && !directPaths[e.InferredFrom] {
			orphanInferred = append(orphanInferred, path)
		}
	}

	// Signal: empty profile — sensor produced nothing useful.
	if directCount == 0 {
		score -= penaltyEmptyProfile
		penalties = append(penalties, ConfidencePenalty{
			Signal: "empty-profile",
			Reason: "no direct observations — sensor was inactive or container was idle for the entire profiling window",
			Points: -penaltyEmptyProfile,
		})
	}

	// Signal: profile duration.
	actual := m.ProfileEnd.Sub(m.ProfileStart)
	switch {
	case actual == 0:
		score -= penaltyZeroDuration
		penalties = append(penalties, ConfidencePenalty{
			Signal: "zero-profile-duration",
			Reason: "profile_start equals profile_end — manifest may not have a valid profiling window",
			Points: -penaltyZeroDuration,
		})
	case actual < minProfileDuration:
		ratio := float64(actual) / float64(minProfileDuration)
		var penalty int
		switch {
		case ratio < 0.25:
			penalty = 20
		case ratio < 0.50:
			penalty = 14
		case ratio < 0.75:
			penalty = 8
		default:
			penalty = 4
		}
		score -= penalty
		penalties = append(penalties, ConfidencePenalty{
			Signal: "short-profile-window",
			Reason: fmt.Sprintf("profile duration %s is below the recommended minimum of %s",
				actual.Round(time.Second), minProfileDuration),
			Points: -penalty,
		})
	}

	// Signal: user manual entries — each indicates a sensor coverage gap.
	if len(userManual) > 0 {
		penalty := min(len(userManual)*penaltyManualPerEntry, penaltyManualCap)
		score -= penalty
		penalties = append(penalties, ConfidencePenalty{
			Signal: "manual-entries",
			Reason: fmt.Sprintf("%d manual %s indicate paths not observed during profiling",
				len(userManual), plural(len(userManual), "entry", "entries")),
			Points: -penalty,
		})
	}

	// Signal: startup-race manual entries — stacks with manual-entries penalty.
	var startupRace int
	for _, e := range userManual {
		if strings.Contains(e.IncludedBecause, "startup-race") {
			startupRace++
		}
	}
	if startupRace > 0 {
		penalty := min(startupRace*penaltyStartupRacePerEntry, penaltyStartupRaceCap)
		score -= penalty
		penalties = append(penalties, ConfidencePenalty{
			Signal: "startup-race",
			Reason: fmt.Sprintf("%d startup-race %s — NRI hook fired after application opened files the sensor could not observe",
				startupRace, plural(startupRace, "entry", "entries")),
			Points: -penalty,
		})
	}

	// Signal: undocumented manual entries — audit risk.
	var undoc int
	for _, e := range userManual {
		if e.IncludedBecause == "" {
			undoc++
		}
	}
	if undoc > 0 {
		penalty := min(undoc*penaltyUndocPerEntry, penaltyUndocCap)
		score -= penalty
		penalties = append(penalties, ConfidencePenalty{
			Signal: "undocumented-manual-entries",
			Reason: fmt.Sprintf("%d manual %s lack an included_because field — add one for SBOM audit traceability",
				undoc, plural(undoc, "entry", "entries")),
			Points: -penalty,
		})
	}

	if score < 0 {
		score = 0
	}

	return ConfidenceResult{
		Score:          score,
		Level:          levelFromScore(score),
		Penalties:      penalties,
		OrphanInferred: orphanInferred,
	}
}

// levelFromScore maps a 0–100 score to a qualitative band.
func levelFromScore(score int) ConfidenceLevel {
	switch {
	case score >= 80:
		return ConfidenceHigh
	case score >= 60:
		return ConfidenceMedium
	case score >= 40:
		return ConfidenceLow
	default:
		return ConfidenceVeryLow
	}
}

// plural returns singular if n == 1, otherwise plural.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
