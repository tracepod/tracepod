// Package reportschema embeds the versioned reachability-report JSON Schema —
// the cross-repo contract the `tracepod cve-report` CLI renders from. WP2 in the
// controller repo owns the canonical schema; this is a committed copy.
//
// The schema file and version.txt are coupled to the version the CLI declares it
// supports (cmd/tracepod.supportedReportSchemaVersion). Bumping the contract is a
// deliberate two-file change — see cmd/tracepod's contract-version test, which
// fails CI if version.txt and the CLI's declared version diverge.
package reportschema

import (
	_ "embed"
	"strings"
)

//go:embed reachability-report.v1.json
var schemaV1 []byte

//go:embed version.txt
var versionFile string

// SchemaBytes returns the committed v1 JSON Schema document.
func SchemaBytes() []byte { return schemaV1 }

// Version is the report schema_version this contract copy declares, read from
// version.txt (e.g. "1.0").
func Version() string { return strings.TrimSpace(versionFile) }
