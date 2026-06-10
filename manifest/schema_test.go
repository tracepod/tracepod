package manifest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tracepod/tracepod/manifest"
)

// schemaPath is the committed JSON Schema for the version the sensor currently
// emits. It is derived from manifest.SchemaVersion, so bumping the version makes
// these tests demand a docs/profile-schema/v<N>.schema.json file. Tests run with
// the package directory as CWD, so the docs/ tree is one level up.
var schemaPath = fmt.Sprintf("../docs/profile-schema/v%d.schema.json", manifest.SchemaVersion)

// compileSchema loads and compiles the committed v2 JSON Schema.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaPath, doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// validate marshals m exactly as the sensor would (json.Marshal is the wire
// path in PostProfile) and asserts it conforms to the committed schema.
func validate(t *testing.T, sch *jsonschema.Schema, m manifest.Manifest) {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse marshalled manifest: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("manifest does not conform to schema:\n%v\n\ndocument:\n%s", err, body)
	}
}

// TestSchemaConformance_assembledManifests validates that every profile the
// sensor assembles validates against the committed JSON Schema (R1 / Tests).
// Table-driven over synthetic event sets including empty, missed-start, and
// multi-restart profiles.
func TestSchemaConformance_assembledManifests(t *testing.T) {
	sch := compileSchema(t)
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	cases := map[string]func() manifest.Manifest{
		"empty": func() manifest.Manifest {
			a := manifest.NewAggregator("empty-ctr", "")
			a.RecordAttach(base, false)
			return a.Snapshot()
		},
		"won-start-with-files": func() manifest.Manifest {
			a := manifest.NewAggregator("won-ctr", "nginx:1.25-alpine")
			a.RecordAttach(base, false)
			a.RecordFile("/usr/sbin/nginx", manifest.SourceDirect,
				[]manifest.AccessMode{manifest.AccessExecute}, base.Add(time.Second))
			a.RecordFile("/etc/nginx/nginx.conf", manifest.SourceDirect,
				[]manifest.AccessMode{manifest.AccessRead}, base.Add(2*time.Second))
			a.RecordInferredELF("/lib/libc.so.6", "/usr/sbin/nginx", base.Add(2*time.Second))
			a.RecordDirectoryInclusion("/usr/share/nginx/html/index.html", "/usr/share/nginx/html", base)
			return a.Snapshot()
		},
		"missed-start": func() manifest.Manifest {
			a := manifest.NewAggregator("missed-ctr", "redis:7")
			a.RecordAttach(base, true) // process already running at attach
			a.RecordFile("/usr/bin/redis-server", manifest.SourceDirect,
				[]manifest.AccessMode{manifest.AccessExecute}, base.Add(time.Second))
			return a.Snapshot()
		},
		"multi-restart": func() manifest.Manifest {
			a := manifest.NewAggregator("restart-ctr-1", "app:v1")
			a.RecordAttach(base, false)
			a.RecordStart("restart-ctr-2", base.Add(30*time.Second))
			a.RecordStart("restart-ctr-3", base.Add(60*time.Second))
			return a.Snapshot()
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			validate(t, sch, build())
		})
	}
}

// TestProfileFixtures_conform validates every committed recorded fixture against
// the matching schema (the controller-repo CI replay path depends on these being
// valid). Skips cleanly when no fixtures have been recorded yet. Fixtures are
// recorded artifacts (testdata/profile-fixtures/README.md) — this guards them
// against drift and accidental hand-edits.
func TestProfileFixtures_conform(t *testing.T) {
	sch := compileSchema(t)
	dir := fmt.Sprintf("../testdata/profile-fixtures/v%d", manifest.SchemaVersion)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no recorded fixtures at %s yet: %v", dir, err)
	}
	var jsons []string
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 5 && e.Name()[len(e.Name())-5:] == ".json" {
			jsons = append(jsons, e.Name())
		}
	}
	if len(jsons) == 0 {
		t.Skipf("no *.json fixtures in %s yet", dir)
	}
	for _, name := range jsons {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(dir + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Errorf("fixture %s does not conform to schema v%d:\n%v", name, manifest.SchemaVersion, err)
			}
		})
	}
}

// TestProfileFixtures_coverScenarios guards that the committed fixture set keeps
// covering the scenarios the controller-side replay needs: at least one
// missed-start profile (process_start_observed=false) and at least one
// won-start profile (true). Skips when no fixtures are recorded yet.
func TestProfileFixtures_coverScenarios(t *testing.T) {
	dir := fmt.Sprintf("../testdata/profile-fixtures/v%d", manifest.SchemaVersion)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no recorded fixtures at %s yet: %v", dir, err)
	}
	var sawTrue, sawFalse, n int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || len(name) < 6 || name[len(name)-5:] != ".json" {
			continue
		}
		raw, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var m manifest.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode fixture %s: %v", name, err)
		}
		n++
		if m.SchemaVersion != manifest.SchemaVersion {
			t.Errorf("fixture %s: schema_version=%d, want %d", name, m.SchemaVersion, manifest.SchemaVersion)
		}
		if len(m.ContainerStarts) < 1 {
			t.Errorf("fixture %s: container_starts must have >=1 entry", name)
		}
		if m.Coverage.ProcessStartObserved {
			sawTrue++
		} else {
			sawFalse++
		}
	}
	if n == 0 {
		t.Skip("no *.json fixtures recorded yet")
	}
	if sawTrue == 0 {
		t.Error("fixture set has no won-start profile (process_start_observed=true)")
	}
	if sawFalse == 0 {
		t.Error("fixture set has no missed-start profile (process_start_observed=false)")
	}
}

// TestSchemaConformance_rejectsMalformed proves the validator is real — a
// document with a bogus source enum and a string schema_version must fail, so a
// silently-passing harness can't mask a genuine drift.
func TestSchemaConformance_rejectsMalformed(t *testing.T) {
	sch := compileSchema(t)
	bad := []byte(`{
		"schema_version": "1",
		"container_id": "c",
		"profile_start": "2026-06-10T12:00:00Z",
		"profile_end": "2026-06-10T12:01:00Z",
		"coverage": {"process_start_observed": false, "attach_time": "2026-06-10T12:00:00Z"},
		"container_starts": [],
		"files": {"/x": {"source": "telepathy", "access_modes": [], "first_seen": "2026-06-10T12:00:00Z", "last_seen": "2026-06-10T12:00:00Z", "count": 0}}
	}`)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err == nil {
		t.Fatal("expected malformed document to fail schema validation, but it passed")
	}
}

// TestSchemaConformance_versionIsIntegerTwo guards the R1 type change: the wire
// field must be the integer 2, never the legacy string "1".
func TestSchemaConformance_versionIsIntegerTwo(t *testing.T) {
	a := manifest.NewAggregator("c", "")
	body, err := json.Marshal(a.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"schema_version":2`)) {
		t.Errorf("expected integer schema_version 2 in wire output, got:\n%s", body)
	}
	if bytes.Contains(body, []byte(`"schema_version":"`)) {
		t.Errorf("schema_version must not be a string:\n%s", body)
	}
}
