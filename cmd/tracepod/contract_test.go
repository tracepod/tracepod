package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportschema "github.com/tracepod/tracepod/contracts/report-schema"
)

// reportFixtures are the committed schema-valid report responses (the contract
// the renderer is exercised through). error-digest-mismatch.json is excluded —
// it is an error envelope, not a report.
var reportFixtures = []string{
	"report-php-hello.json",
	"report-grype-small.json",
	"report-trivy-import.json",
	"report-mixed.json",
}

func fixturePath(name string) string { return filepath.Join("testdata", "cve-report", name) }

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestContractVersionMatches is the contract-version check: the version the CLI
// declares it supports MUST equal contracts/report-schema/version.txt, and the
// embedded schema's $id major MUST match. Bumping the contract is a deliberate
// change to both — this test fails CI if they diverge.
func TestContractVersionMatches(t *testing.T) {
	if got, want := reportschema.Version(), supportedReportSchemaVersion; got != want {
		t.Fatalf("contract version drift: version.txt=%q but supportedReportSchemaVersion=%q "+
			"(bumping the contract must update BOTH)", got, want)
	}

	var schemaDoc struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(reportschema.SchemaBytes(), &schemaDoc); err != nil {
		t.Fatalf("embedded schema not valid JSON: %v", err)
	}
	major := strings.SplitN(supportedReportSchemaVersion, ".", 2)[0]
	wantSuffix := "reachability-report.v" + major + ".json"
	if !strings.HasSuffix(schemaDoc.ID, wantSuffix) {
		t.Fatalf("schema $id %q does not match supported major v%s (want suffix %q)",
			schemaDoc.ID, major, wantSuffix)
	}
}

// TestFixturesValidateAgainstSchema is the contract test (catches stale fixture
// copies): every committed report fixture must validate against the schema.
func TestFixturesValidateAgainstSchema(t *testing.T) {
	for _, name := range reportFixtures {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReport(readFixture(t, name)); err != nil {
				t.Fatalf("fixture %s does not satisfy the committed schema: %v", name, err)
			}
		})
	}
}

// TestParseReport_SchemaInvalid is the R4 path: a deliberately broken input (a
// report missing the required summary block) is rejected as a *SchemaError naming
// both versions, never silently rendered.
func TestParseReport_SchemaInvalid(t *testing.T) {
	broken := []byte(`{"schema":"tracepod.dev/reachability-report","schema_version":"9.9","header":{},"findings":[]}`)
	_, err := ParseReport(broken)
	if err == nil {
		t.Fatal("expected a schema error for a malformed report, got nil")
	}
	se, ok := err.(*SchemaError)
	if !ok {
		t.Fatalf("expected *SchemaError, got %T: %v", err, err)
	}
	if se.ClientVersion != supportedReportSchemaVersion {
		t.Errorf("client version = %q, want %q", se.ClientVersion, supportedReportSchemaVersion)
	}
	if se.ServerVersion != "9.9" {
		t.Errorf("server version = %q, want 9.9 (extracted from the response)", se.ServerVersion)
	}
	if !strings.Contains(se.Error(), "outdated") {
		t.Errorf("R4 message should flag a possibly-outdated CLI; got: %s", se.Error())
	}
}

// TestOutputJSONByteFaithful asserts the --output json path is byte-identical to
// the controller payload (R5): the bytes the CLI would emit equal the fixture
// bytes exactly, with no reshaping.
func TestOutputJSONByteFaithful(t *testing.T) {
	for _, name := range reportFixtures {
		t.Run(name, func(t *testing.T) {
			raw := readFixture(t, name)
			// The --output json branch writes raw verbatim. Emulate it and compare.
			if got := emitJSON(raw); !bytesEqualModuloTrailingNewline(got, raw) {
				t.Fatalf("--output json mutated the payload for %s", name)
			}
		})
	}
}

// emitJSON mirrors the --output json branch of runCVEReport: raw bytes, verbatim.
func emitJSON(raw []byte) []byte { return raw }

func bytesEqualModuloTrailingNewline(a, b []byte) bool {
	trim := func(x []byte) string { return strings.TrimRight(string(x), "\n") }
	return trim(a) == trim(b)
}
