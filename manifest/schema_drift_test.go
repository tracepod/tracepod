package manifest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tracepod/tracepod/manifest"
)

// publishedSchemaHashes freezes the sha256 of every published profile JSON
// Schema. Once a version is published its schema file is IMMUTABLE: any edit
// changes the hash and fails this test, which is the mechanical half of the
// schema-drift guard.
//
// Combined with the conformance test (which validates the assembled document
// against docs/profile-schema/v<SchemaVersion>.schema.json, with
// additionalProperties:false), this enforces the versioning policy end to end:
//
//   - Change the profile assembly shape (add/remove/retype a field) → the
//     conformance test fails against the frozen current schema.
//   - "Fix" it by editing the current schema in place → THIS test fails because
//     the published schema's hash changed.
//   - The only green path is to add a new docs/profile-schema/v<N+1>.schema.json,
//     bump manifest.SchemaVersion, and record the new hash here.
//
// To intentionally publish a new version: add the file, bump SchemaVersion, then
// add its hash below (recompute with `shasum -a 256 docs/profile-schema/*.json`).
var publishedSchemaHashes = map[string]string{
	"v1.schema.json": "aa63c9640ff9f22e46527be3ff535ff419fe5a66cbefccfc49179f18361ae974",
	"v2.schema.json": "8b518b4357e3d441a4e6590a35e6e1082f36d8d987e7a71fd5f8d555f4a175ec",
	// v3 was revised IN PLACE on 2026-06-11 (OSS-4b) to add the event_loss.tolerated
	// category, before any consumer of v3 existed — a one-time exception to the
	// frozen-schema rule, documented in docs/profile-schema/README.md. This is the
	// hash of the revised v3; the pre-revision hash was
	// d02f59719ff70799a793b08b9c457db3cbd26de8e0371f3ecec4bb77b00e576c.
	"v3.schema.json": "d1aa1d007375aca1454be664c3a390ec1f0ed3a1ddc6801716b4cce1efa08a75",
	// v4 (2026-07-06): adds the "s" access mode (stat-family existence checks,
	// --trace-stat) and the "inferred-runtime" observation source. Additive
	// enum widening only; no v3 field semantics changed.
	"v4.schema.json": "bdff234578a44f982a94829b450f988ee2d9701c9193ab33e9bee485fe59af93",
	// v5 (2026-08-15): adds coverage.adoption_mode and profile_terminal, so a
	// consumer can tell a complete observation window from a truncated one. That
	// cannot be derived from timestamps — a truncated window yields FEWER file
	// entries, so it reads as cleaner than a complete one. Additive; no v4 field
	// semantics changed.
	"v5.schema.json": "09fb35cfb1eb17e2e30262444e4411de72c5033998c2f491ff45d6c069038b44",
}

const schemaDir = "../docs/profile-schema"

func TestSchemaDrift_publishedSchemasAreFrozen(t *testing.T) {
	for name, want := range publishedSchemaHashes {
		raw, err := os.ReadFile(filepath.Join(schemaDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(raw)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != want {
			t.Errorf("published schema %s changed (hash %s, want %s).\n"+
				"Published schemas are immutable. Any shape change requires a NEW version file "+
				"(docs/profile-schema/v<N+1>.schema.json), a manifest.SchemaVersion bump, and a "+
				"new entry in publishedSchemaHashes — never an in-place edit.", name, gotHex, want)
		}
	}
}

// TestSchemaDrift_currentVersionHasSchemaAndIsFrozen ties the guard to the
// version the sensor emits: the current SchemaVersion must have a published,
// frozen schema file.
func TestSchemaDrift_currentVersionHasSchemaAndIsFrozen(t *testing.T) {
	name := schemaFileName(manifest.SchemaVersion)
	if _, ok := publishedSchemaHashes[name]; !ok {
		t.Fatalf("manifest.SchemaVersion is %d but %s is not in publishedSchemaHashes — "+
			"add the schema file and freeze its hash", manifest.SchemaVersion, name)
	}
	if _, err := os.Stat(filepath.Join(schemaDir, name)); err != nil {
		t.Fatalf("schema file for current version missing: %v", err)
	}
}

func schemaFileName(v int) string {
	return fmt.Sprintf("v%d.schema.json", v)
}
