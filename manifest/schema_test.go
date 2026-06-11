package manifest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
		// v3: a fully-instrumented profile with nonzero event_loss must validate.
		"event-loss-nonzero": func() manifest.Manifest {
			a := manifest.NewAggregator("lossy-ctr", "app:v1")
			a.RecordAttach(base, false)
			r := &fakeLossReader{byStage: map[string]uint64{
				manifest.LossStageBPFReserveFailed: 0,
				manifest.LossStageDecodeFailed:     0,
				manifest.LossStageUntrackedCgroup:  0,
			}}
			a.SetLossReader(r)
			r.byStage[manifest.LossStageBPFReserveFailed] = 17
			return a.Snapshot()
		},
		// v3: the not_instrumented escape hatch (no reader) must validate too.
		"event-loss-not-instrumented": func() manifest.Manifest {
			a := manifest.NewAggregator("uninstrumented-ctr", "app:v1")
			a.RecordAttach(base, false)
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

// TestProfileFixtures_eventLoss guards the schema-v3 event_loss invariants over
// the recorded fixture set (R5): every fixture carries event_loss with the sum
// invariant intact and nothing falsely zeroed; the induced-loss fixture proves a
// nonzero total is reachable and recorded; every other fixture proves a true
// zero. Skips cleanly when no v3 fixtures have been recorded yet.
func TestProfileFixtures_eventLoss(t *testing.T) {
	dir := fmt.Sprintf("../testdata/profile-fixtures/v%d", manifest.SchemaVersion)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no recorded fixtures at %s yet: %v", dir, err)
	}

	var n, sawNonzero, sawZero int
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
		el := m.EventLoss

		// Sum invariant holds for every fixture — total counts HARD losses only;
		// tolerated is excluded by construction.
		var sum uint64
		for _, v := range el.ByStage {
			sum += v
		}
		if el.Total != sum {
			t.Errorf("%s: event_loss.total=%d != sum(by_stage)=%d", name, el.Total, sum)
		}
		// A recorded fixture is from a live sensor: every audited stage (hard AND
		// tolerated) must be instrumented (zero-is-a-claim), so not_instrumented
		// must be empty and by_stage/tolerated must carry all canonical stages.
		if len(el.NotInstrumented) != 0 {
			t.Errorf("%s: recorded fixture has not_instrumented=%v — a live sensor instruments every stage", name, el.NotInstrumented)
		}
		for _, st := range manifest.LossStages {
			if _, ok := el.ByStage[st]; !ok {
				t.Errorf("%s: by_stage missing instrumented stage %q", name, st)
			}
		}
		for _, st := range manifest.ToleratedStages {
			if _, ok := el.Tolerated[st]; !ok {
				t.Errorf("%s: tolerated missing instrumented stage %q", name, st)
			}
			// A tolerated stage must never leak into the hard bucket (regression
			// guard: path_read_failed lives in tolerated and nowhere else).
			if _, ok := el.ByStage[st]; ok {
				t.Errorf("%s: tolerated stage %q must not appear in by_stage", name, st)
			}
		}

		isInduced := strings.HasPrefix(name, "induced-loss")
		switch {
		case isInduced:
			if el.Total == 0 {
				t.Errorf("%s: induced-loss fixture must have event_loss.total > 0", name)
			}
			if el.ByStage[manifest.LossStageBPFReserveFailed] == 0 {
				t.Errorf("%s: induced-loss fixture expected bpf_reserve_failed > 0, got by_stage=%v", name, el.ByStage)
			}
			sawNonzero++
		default:
			// Normal scenarios: the strict-zero gate on HARD losses holds even
			// though tolerated.path_read_failed may carry its intrinsic idle floor
			// (0-2). This is the whole point of the tolerated category — a nonzero
			// path-read floor must NOT taint total.
			if el.Total != 0 {
				t.Errorf("%s: normal fixture must have event_loss.total == 0, got %d (by_stage=%v)", name, el.Total, el.ByStage)
			}
			sawZero++
		}
	}

	if n == 0 {
		t.Skip("no *.json fixtures recorded yet")
	}
	if sawZero == 0 {
		t.Error("fixture set has no true-zero event_loss profile (normal scenario)")
	}
	if sawNonzero == 0 {
		t.Error("fixture set has no induced-loss profile (event_loss.total > 0) — record one with a shrunken ring buffer")
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

// TestSchemaConformance_versionIsCurrentInteger guards the schema_version wire
// type: it must be the current integer (never the legacy string "1").
func TestSchemaConformance_versionIsCurrentInteger(t *testing.T) {
	a := manifest.NewAggregator("c", "")
	body, err := json.Marshal(a.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`"schema_version":%d`, manifest.SchemaVersion)
	if !bytes.Contains(body, []byte(want)) {
		t.Errorf("expected integer %q in wire output, got:\n%s", want, body)
	}
	if bytes.Contains(body, []byte(`"schema_version":"`)) {
		t.Errorf("schema_version must not be a string:\n%s", body)
	}
}
