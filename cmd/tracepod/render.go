package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// renderOptions controls the human renderer.
type renderOptions struct {
	severity string // minimum severity to show in the table: critical|high|medium|low|negligible|all
	verbose  bool   // show the coverage-score breakdown + attribution evidence
}

// defaultSeverity is the table's default scope. We lead with the actionable slice
// (R2): a bare total overstates the story, so the table defaults to High+Critical
// while the summary lines always report the full counts.
const defaultSeverity = "high"

var severityThresholds = map[string]bool{
	"critical": true, "high": true, "medium": true,
	"low": true, "negligible": true, "all": true,
}

// validateSeverity normalises and checks a --severity value.
func validateSeverity(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return defaultSeverity, nil
	}
	if !severityThresholds[s] {
		return "", fmt.Errorf("invalid --severity %q (want one of: critical, high, medium, low, negligible, all)", s)
	}
	return s, nil
}

// showAtSeverity reports whether a finding's severity passes the threshold.
func showAtSeverity(findingSeverity, threshold string) bool {
	if threshold == "all" {
		return true
	}
	// Unknown/other severities only appear under "all" so the named thresholds
	// stay a clean most-severe-first prefix.
	if severityRank(findingSeverity) > severityRank("negligible") {
		return false
	}
	return severityRank(findingSeverity) <= severityRank(threshold)
}

// classCounts holds a classification breakdown for one finding subset.
type classCounts struct {
	total, loaded, notLoaded, indeterminate, unmatched int
}

func (c classCounts) line() string {
	return fmt.Sprintf("%d findings: %d loaded, %d not loaded, %d indeterminate, %d unmatched",
		c.total, c.loaded, c.notLoaded, c.indeterminate, c.unmatched)
}

func countFindings(fs []ReportFinding) classCounts {
	var c classCounts
	for _, f := range fs {
		c.total++
		switch f.Classification {
		case classLoaded:
			c.loaded++
		case classNotLoaded:
			c.notLoaded++
		case classIndeterminate:
			c.indeterminate++
		case classUnmatched:
			c.unmatched++
		}
	}
	return c
}

// RenderHuman writes the default human-readable report (R2/R3). The summary lines
// are the headline; the table is scoped by opts.severity; the capability line and
// the verbatim known-limitations footer always close the output.
func RenderHuman(w io.Writer, rep *Report, opts renderOptions) {
	h := rep.Header

	// Context line.
	fmt.Fprintf(w, "Reachability report — %s/%s (profile %s)\n",
		h.Namespace, h.Deployment, h.ProfileID)
	fmt.Fprintf(w, "  image  %s\n", h.ImageRef)
	fmt.Fprintf(w, "  scan   %s %s · %s · generated %s\n",
		h.Scanner, h.GrypeVersion, findingsSourceLabel(h.FindingsSource), h.GeneratedAt)

	// Summary headline: the authoritative all-severities counts from the
	// controller, then the actionable High+Critical cut derived from the findings.
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", summaryFromReport(rep).line())
	hc := countFindings(filterHighCritical(rep.Findings))
	fmt.Fprintf(w, "High+Critical — %s\n", hc.line())

	if opts.verbose {
		renderVerbose(w, rep)
	}

	// Table, scoped to the requested severity.
	threshold := opts.severity
	rows := filterBySeverity(rep.Findings, threshold)
	sortFindings(rows)

	fmt.Fprintln(w)
	if len(rows) == 0 {
		fmt.Fprintf(w, "No findings at or above severity %q.\n", threshold)
	} else {
		renderTable(w, rows)
		if threshold != "all" && len(rows) < rep.Summary.Total {
			fmt.Fprintf(w, "\nShowing %d of %d findings (severity ≥ %s). Use --severity all to see every finding.\n",
				len(rows), rep.Summary.Total, threshold)
		}
	}

	// R3: server-driven capability line. Exactly one factual trailing line, only
	// when the response says VEX export is unavailable. No tier logic client-side.
	if !rep.Capabilities.VEXExport {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "VEX export (not_affected attestations from not_loaded findings) is available in Tracepod Pro.")
	}

	// R2: always print the report's own known-limitations footer, verbatim.
	fmt.Fprintln(w)
	fmt.Fprintln(w, rep.Footer)
}

// summaryFromReport uses the controller's authoritative summary counts (never
// recomputed) for the all-severities headline.
func summaryFromReport(rep *Report) classCounts {
	return classCounts{
		total:         rep.Summary.Total,
		loaded:        rep.Summary.Loaded,
		notLoaded:     rep.Summary.NotLoaded,
		indeterminate: rep.Summary.Indeterminate,
		unmatched:     rep.Summary.Unmatched,
	}
}

func filterHighCritical(fs []ReportFinding) []ReportFinding {
	out := make([]ReportFinding, 0, len(fs))
	for _, f := range fs {
		if isHighOrCritical(f.Severity) {
			out = append(out, f)
		}
	}
	return out
}

func filterBySeverity(fs []ReportFinding, threshold string) []ReportFinding {
	out := make([]ReportFinding, 0, len(fs))
	for _, f := range fs {
		if showAtSeverity(f.Severity, threshold) {
			out = append(out, f)
		}
	}
	return out
}

// sortFindings orders rows severity-then-classification (R2), with CVE as a
// stable tie-breaker so output is deterministic.
func sortFindings(fs []ReportFinding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if ca, cb := classificationRank(a.Classification), classificationRank(b.Classification); ca != cb {
			return ca < cb
		}
		return a.CVE < b.CVE
	})
}

func renderTable(w io.Writer, rows []ReportFinding) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCLASSIFICATION\tCVE\tPACKAGE\tVERSION\tEVIDENCE")
	for _, f := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, classificationLabel(f.Classification), f.CVE,
			f.Package, f.Version, evidenceSummary(f))
	}
	tw.Flush()
}

// evidenceSummary is a one-line human gloss of the structured evidence block.
func evidenceSummary(f ReportFinding) string {
	switch f.Classification {
	case classLoaded:
		if f.Evidence.Loaded != nil && f.Evidence.Loaded.Path != "" {
			if f.Evidence.Loaded.Reason != "" {
				return fmt.Sprintf("%s (%s)", f.Evidence.Loaded.Path, f.Evidence.Loaded.Reason)
			}
			return f.Evidence.Loaded.Path
		}
	case classNotLoaded:
		if f.Evidence.NotLoaded != nil {
			return fmt.Sprintf("not observed in %ds window", f.Evidence.NotLoaded.ProfilingDurationSeconds)
		}
	}
	return f.Evidence.Reason
}

func findingsSourceLabel(s string) string {
	switch s {
	case "grype-scan":
		return "server-side grype scan"
	case "grype-import":
		return "imported grype findings"
	case "trivy-import":
		return "imported trivy findings"
	default:
		return s
	}
}

func renderVerbose(w io.Writer, rep *Report) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Coverage: %d\n", rep.Header.CoverageScore)
	if c := rep.Coverage; c != nil && !c.Legacy {
		fmt.Fprintf(w, "  composite %d (%s)%s\n", c.Score, c.Band, cappedSuffix(c.Capped))
		for _, name := range []string{"duration", "process_start", "restart", "plateau", "diversity"} {
			comp := coverageComponent(c, name)
			fmt.Fprintf(w, "    %-14s %3d  (weight %.2f)  %s\n", name, comp.Score, comp.Weight, comp.Detail)
		}
	} else {
		fmt.Fprintln(w, "  (no component breakdown — legacy profile)")
	}

	a := rep.Attribution
	fmt.Fprintf(w, "Attribution (syft %s): %d/%d paths attributed (%.1f%% net)\n",
		a.SyftVersion, a.AttributedPaths, a.TotalPaths, a.CoveragePct)
	ecos := make([]string, 0, len(a.PerEcosystem))
	for k := range a.PerEcosystem {
		ecos = append(ecos, k)
	}
	sort.Strings(ecos)
	for _, k := range ecos {
		fmt.Fprintf(w, "    %-10s %d\n", k, a.PerEcosystem[k])
	}
	for _, warn := range a.Warnings {
		fmt.Fprintf(w, "    warning: %s\n", warn)
	}
}

func cappedSuffix(capped bool) string {
	if capped {
		return " (capped)"
	}
	return ""
}

func coverageComponent(c *CoverageScore, name string) CoverageComponent {
	switch name {
	case "duration":
		return c.Components.Duration
	case "process_start":
		return c.Components.ProcessStart
	case "restart":
		return c.Components.Restart
	case "plateau":
		return c.Components.Plateau
	case "diversity":
		return c.Components.Diversity
	default:
		return CoverageComponent{}
	}
}
