package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	reportschema "github.com/tracepod/tracepod/contracts/report-schema"
)

// supportedReportSchemaVersion is the reachability-report schema_version this CLI
// build renders. It is the client half of the cross-repo contract: it MUST equal
// contracts/report-schema/version.txt (TestContractVersionMatches enforces this,
// failing CI on divergence) and its major MUST match the embedded schema. Bumping
// the contract is a deliberate change to both this constant and version.txt.
const supportedReportSchemaVersion = "1.0"

// Report mirrors reachability-report.v1.json — the controller-served payload. The
// CLI is a pure renderer: it never computes a classification, only reads these
// fields. Unknown additional fields are ignored (forward compatibility, R5);
// missing required fields are caught by schema validation (R4), not here.
type Report struct {
	Schema        string             `json:"schema"`
	SchemaVersion string             `json:"schema_version"`
	Header        ReportHeader       `json:"header"`
	Summary       ReportSummary      `json:"summary"`
	Coverage      *CoverageScore     `json:"coverage"`
	Attribution   ReportAttribution  `json:"attribution"`
	Findings      []ReportFinding    `json:"findings"`
	Capabilities  ReportCapabilities `json:"capabilities"`
	Footer        string             `json:"footer"`
}

// ReportHeader carries provenance + pinned tool versions + the profiling window.
type ReportHeader struct {
	ImageRef            string `json:"image_ref"`
	ImageDigest         string `json:"image_digest"`
	Platform            string `json:"platform"`
	ProfileID           string `json:"profile_id"`
	Namespace           string `json:"namespace"`
	Deployment          string `json:"deployment"`
	Container           string `json:"container,omitempty"`
	WindowStart         string `json:"window_start"`
	WindowEnd           string `json:"window_end"`
	DurationSeconds     int64  `json:"duration_seconds"`
	ObservedPathCount   int    `json:"observed_path_count"`
	ObservedEventCount  uint64 `json:"observed_event_count"`
	CoverageScore       int    `json:"coverage_score"`
	SensorVersion       string `json:"sensor_version"`
	SyftVersion         string `json:"syft_version"`
	GrypeVersion        string `json:"grype_version"`
	Scanner             string `json:"scanner"`
	ScannerDBTimestamp  string `json:"scanner_db_timestamp"`
	FindingsSource      string `json:"findings_source"`
	GeneratedAt         string `json:"generated_at"`
	KnownLimitationsRef string `json:"known_limitations_ref"`
}

// ReportSummary is the authoritative classification headline (counts come from
// the controller; the CLI never recomputes them).
type ReportSummary struct {
	Total         int `json:"total"`
	Loaded        int `json:"loaded"`
	NotLoaded     int `json:"not_loaded"`
	Indeterminate int `json:"indeterminate"`
	Unmatched     int `json:"unmatched"`
}

// ReportAttribution is the WP1 coverage-evidence surface (rendered under --verbose).
type ReportAttribution struct {
	SyftVersion     string         `json:"syft_version"`
	TotalPaths      int            `json:"total_paths"`
	AttributedPaths int            `json:"attributed_paths"`
	NetAttributed   int            `json:"net_attributed"`
	CoveragePct     float64        `json:"coverage_pct"`
	PerEcosystem    map[string]int `json:"per_ecosystem"`
	Warnings        []string       `json:"warnings,omitempty"`
}

// ReportFinding is one finding with its server-decided classification + evidence.
type ReportFinding struct {
	CVE            string          `json:"cve"`
	Severity       string          `json:"severity"`
	Purl           string          `json:"purl"`
	Package        string          `json:"package"`
	Version        string          `json:"version"`
	Ecosystem      string          `json:"ecosystem"`
	Classification string          `json:"classification"`
	MatchedPurl    string          `json:"matched_purl,omitempty"`
	Evidence       FindingEvidence `json:"evidence"`
}

// FindingEvidence is the audit trail behind a verdict.
type FindingEvidence struct {
	Reason    string             `json:"reason"`
	Loaded    *LoadEvidence      `json:"loaded,omitempty"`
	NotLoaded *NotLoadedEvidence `json:"not_loaded,omitempty"`
}

// LoadEvidence is the example path/access proving a package was loaded.
type LoadEvidence struct {
	Reason     string `json:"reason"`
	Path       string `json:"path"`
	Access     string `json:"access"`
	FirstSeen  string `json:"first_seen,omitempty"`
	RequiredBy string `json:"required_by,omitempty"`
}

// NotLoadedEvidence is the structured (never wall-clock-prose) not_loaded evidence.
type NotLoadedEvidence struct {
	ProfilingDurationSeconds int64  `json:"profiling_duration_seconds"`
	ObservedPathCount        int    `json:"observed_path_count"`
	ObservedEventCount       uint64 `json:"observed_event_count"`
	CoverageScore            int    `json:"coverage_score"`
	Statement                string `json:"statement"`
}

// ReportCapabilities is the server-driven capability block (R3). The CLI renders
// it verbatim — no licence logic lives client-side.
type ReportCapabilities struct {
	VEXExport bool `json:"vex_export"`
}

// Classification values (the four schema enum states the renderer ranks/labels).
const (
	classLoaded        = "loaded"
	classNotLoaded     = "not_loaded"
	classIndeterminate = "indeterminate"
	classUnmatched     = "unmatched"
)

// classificationRank orders classifications within a severity band (R2 sort:
// severity-then-classification). loaded first — the actionable verdict.
func classificationRank(c string) int {
	switch c {
	case classLoaded:
		return 0
	case classNotLoaded:
		return 1
	case classIndeterminate:
		return 2
	case classUnmatched:
		return 3
	default:
		return 4
	}
}

// classificationLabel is the human column text.
func classificationLabel(c string) string {
	switch c {
	case classNotLoaded:
		return "not loaded"
	default:
		return c
	}
}

// severityRank orders severities most-severe-first. Unknown severities sort last
// (rendering is forward-compatible with severities the controller may add).
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "negligible":
		return 4
	case "unknown", "":
		return 5
	default:
		return 6
	}
}

// isHighOrCritical reports whether a severity is in the actionable High+Critical
// slice (R2's honest, sellable cut).
func isHighOrCritical(s string) bool {
	r := severityRank(s)
	return r == severityRank("critical") || r == severityRank("high")
}

// SchemaError signals a controller response that does not satisfy the committed
// schema (R4): distinct from a connection failure, it means the CLI may be out of
// date relative to the controller. It carries both versions for the message.
type SchemaError struct {
	ClientVersion string
	ServerVersion string
	Detail        string
}

func (e *SchemaError) Error() string {
	server := e.ServerVersion
	if server == "" {
		server = "unknown"
	}
	return fmt.Sprintf(
		"controller response does not match the report schema this CLI supports "+
			"(CLI supports schema_version %s, controller sent %s) — the CLI may be "+
			"outdated relative to the controller; upgrade tracepod. Detail: %s",
		e.ClientVersion, server, e.Detail)
}

var compiledReportSchema = mustCompileReportSchema()

func mustCompileReportSchema() *jsonschema.Schema {
	var doc any
	if err := json.Unmarshal(reportschema.SchemaBytes(), &doc); err != nil {
		panic("embedded report schema is not valid JSON: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("reachability-report.json", doc); err != nil {
		panic("add report schema resource: " + err.Error())
	}
	sch, err := c.Compile("reachability-report.json")
	if err != nil {
		panic("compile report schema: " + err.Error())
	}
	return sch
}

// ParseReport validates raw controller bytes against the committed schema and, if
// valid, decodes them into a Report. A schema failure is a *SchemaError (R4); only
// documented fields are read, unknown fields are ignored (R5).
func ParseReport(raw []byte) (*Report, error) {
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		return nil, &SchemaError{
			ClientVersion: supportedReportSchemaVersion,
			ServerVersion: serverSchemaVersion(raw),
			Detail:        "response is not valid JSON: " + err.Error(),
		}
	}
	if err := compiledReportSchema.Validate(inst); err != nil {
		return nil, &SchemaError{
			ClientVersion: supportedReportSchemaVersion,
			ServerVersion: serverSchemaVersion(raw),
			Detail:        oneLine(err.Error()),
		}
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, &SchemaError{
			ClientVersion: supportedReportSchemaVersion,
			ServerVersion: serverSchemaVersion(raw),
			Detail:        "decode: " + err.Error(),
		}
	}
	return &rep, nil
}

// serverSchemaVersion best-effort extracts schema_version from a raw response so
// the R4 message can name the controller's version even when the rest is invalid.
func serverSchemaVersion(raw []byte) string {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.SchemaVersion
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
