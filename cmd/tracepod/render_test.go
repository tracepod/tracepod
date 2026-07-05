package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "regenerate golden output files")

// goldenCases pin the human renderer's output for each committed fixture across
// the severity filter, --verbose, and the default actionable-slice view. They
// cover the all-severities + High+Critical summary lines, the capability line,
// and the verbatim known-limitations footer (R2/R3).
var goldenCases = []struct {
	name    string
	fixture string
	opts    renderOptions
}{
	{"mixed-default", "report-mixed.json", renderOptions{severity: "high"}},
	{"mixed-all", "report-mixed.json", renderOptions{severity: "all"}},
	{"mixed-critical", "report-mixed.json", renderOptions{severity: "critical"}},
	{"mixed-verbose-all", "report-mixed.json", renderOptions{severity: "all", verbose: true}},
	{"php-hello-default", "report-php-hello.json", renderOptions{severity: "high"}},
	{"php-hello-critical", "report-php-hello.json", renderOptions{severity: "critical"}},
	{"php-hello-verbose", "report-php-hello.json", renderOptions{severity: "high", verbose: true}},
	{"grype-small-all", "report-grype-small.json", renderOptions{severity: "all"}},
	{"trivy-import-all", "report-trivy-import.json", renderOptions{severity: "all"}},
}

func TestRenderHuman_Golden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := ParseReport(readFixture(t, tc.fixture))
			if err != nil {
				t.Fatalf("parse %s: %v", tc.fixture, err)
			}
			var buf bytes.Buffer
			RenderHuman(&buf, rep, tc.opts)
			got := buf.Bytes()

			goldenFile := filepath.Join("testdata", "cve-report", "golden", tc.name+".txt")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(goldenFile), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenFile, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(goldenFile)
			if err != nil {
				t.Fatalf("read golden %s (run `go test -run TestRenderHuman_Golden -update`): %v", goldenFile, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("rendered output for %s differs from golden %s.\n--- got ---\n%s\n--- want ---\n%s",
					tc.name, goldenFile, got, want)
			}
		})
	}
}

// TestRenderHuman_HeadlineLines asserts the two summary lines are always present
// and that the High+Critical line reflects the actionable cut (R2). This guards
// the headline independently of the full golden bytes.
func TestRenderHuman_HeadlineLines(t *testing.T) {
	rep, err := ParseReport(readFixture(t, "report-php-hello.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	RenderHuman(&buf, rep, renderOptions{severity: "high"})
	out := buf.String()

	// All-severities line uses the controller's authoritative totals.
	wantAll := summaryFromReport(rep).line()
	if !strings.Contains(out, wantAll) {
		t.Errorf("missing all-severities summary line %q", wantAll)
	}
	// High+Critical line is the derived actionable slice and must be smaller.
	hc := countFindings(filterHighCritical(rep.Findings))
	if hc.total >= rep.Summary.Total {
		t.Fatalf("test fixture no longer demonstrates a smaller actionable slice (hc=%d total=%d)", hc.total, rep.Summary.Total)
	}
	if !strings.Contains(out, "High+Critical — "+hc.line()) {
		t.Errorf("missing High+Critical summary line; got:\n%s", out)
	}
	// Footer is printed verbatim.
	if !strings.Contains(out, rep.Footer) {
		t.Error("known-limitations footer not printed verbatim")
	}
}

// TestRenderHuman_CapabilityLine asserts R3: exactly one Pro line when
// vex_export=false, and none when the server reports it true.
func TestRenderHuman_CapabilityLine(t *testing.T) {
	rep, err := ParseReport(readFixture(t, "report-mixed.json"))
	if err != nil {
		t.Fatal(err)
	}

	var off bytes.Buffer
	RenderHuman(&off, rep, renderOptions{severity: "all"})
	if n := strings.Count(off.String(), "available in Tracepod Pro"); n != 1 {
		t.Errorf("vex_export=false should print exactly one Pro line, got %d", n)
	}

	rep.Capabilities.VEXExport = true // still a schema-valid value
	var on bytes.Buffer
	RenderHuman(&on, rep, renderOptions{severity: "all"})
	if strings.Contains(on.String(), "available in Tracepod Pro") {
		t.Error("vex_export=true must not print the Pro line")
	}
}
