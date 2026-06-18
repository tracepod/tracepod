# NOTES — OSS-2: `tracepod cve-report` thin rendering client

Working branch: `feat/oss-2-cve-report`. (OSS-3 notes archived as `NOTES-OSS3.md`.)

A pure rendering client of the controller's Lite-served reachability API. No
classification/matching/scoring/gating client-side — the engine is controller-only.

## What was built

### Contract (single source)
- `contracts/report-schema/reachability-report.v1.json` — committed copy of the
  controller's schema (`github.com/josemota/ebpf-hardener` →
  `internal/controller/reachability/schema/`). Embedded via the `reportschema`
  Go package (`contracts/report-schema/embed.go`).
- `contracts/report-schema/version.txt` (`1.0`) is coupled to
  `cmd/tracepod.supportedReportSchemaVersion`. `TestContractVersionMatches` fails
  CI if they diverge, and asserts the schema `$id` major matches — bumping the
  contract is a deliberate two-file change. Wired as an explicit CI step.

### Command (`cmd/tracepod/`)
- `report.go` — Report types mirroring the schema; `ParseReport` validates against
  the embedded schema then decodes. Schema failure → `*SchemaError` naming both
  versions (R4). Unknown fields ignored (R5); severity + classification ranks.
- `render.go` — human renderer. Two summary lines (authoritative all-severities
  from `summary`, derived `High+Critical` cut); table sorted
  severity-then-classification-then-CVE; `--severity` threshold (default `high` —
  leads with the actionable slice); `--verbose` coverage + attribution; the R3
  capability line printed **only** when `capabilities.vex_export=false`; the
  report footer printed verbatim.
- `cvereport.go` — client + flags. `--findings` → `POST …/reports/import?profile_id=`
  (sync); default → `POST …/reports` (202 + async) then poll `GET …/reports/{id}`.
  Numeric arg = profile-id; workload name resolved via the profiles list.
  `--output json` writes the payload byte-for-byte. `--controller-url` bypasses the
  port-forward (local Lite-controller verification).

### Tests
- `contract_test.go` — every fixture validates against the schema; the
  contract-version check; a deliberately-broken input for the R4 path;
  `--output json` byte-faithfulness.
- `render_test.go` — golden output per fixture × severity/verbose
  (`testdata/cve-report/golden/`, regen with `-update`); headline + capability-line
  assertions.
- `cvereport_test.go` — `--findings`/create request construction; numeric
  passthrough; server-error message preservation.

### Fixtures (`cmd/tracepod/testdata/cve-report/`)
- `report-php-hello.json` — the WP2-V headline, recorded from the **real**
  production engine via `hack/wp2gate --report` in the controller repo (759
  findings; 97 High+Critical of which 35 loaded; deterministic timestamps). Source
  of truth committed in neeva PR #15.
- `report-grype-small.json` / `report-trivy-import.json` / `error-digest-mismatch.json`
  — copied from the controller's handler contract fixtures.
- `report-mixed.json` — small, hand-authored + schema-validated, covers all four
  classifications incl. `indeterminate` (which no recorded fixture has) and the
  full severity spread.

## Reconciliation finding (WP0 API-shape drift)
The current controller serves `GET /api/v1/profiles` as a `{"profiles":[…]}`
**envelope**, not the bare array the existing client decoded — so the pre-existing
`profile list` was already broken against the live controller. Fixed defensively
(accept both shapes) in `decodeProfileList` (api.go) and `listProfilesRaw`
(cvereport.go). Light fix; no second task absorbed.

## e2e (live Lite controller, k8s-dev VM)
Ran the controller standalone (`TRACEPOD_AUTH_DISABLED=true`,
`--db-path …/e2e.db`, grype on PATH) on `:8088` and drove the CLI via
`--controller-url`:
- missing profile id → live `controller error (HTTP 404): profile not found` (R4).
- `--findings php.grype.json php-hello --namespace acme-legacy` → full report
  (`imported grype findings`, 795 findings / 97 H+C / 35 loaded).
- `--output json | jq .summary,.capabilities` → byte-faithful; `vex_export:false`.
- default (no `--findings`) on profile id → async create+poll → `server-side grype
  scan` report. All exit 0 / errors exit 1.

NB: the recorded profile's session image was a **tag** (no digest); the
controller's POST/import paths require a digest, so the e2e pinned the session
image to `…@sha256:…` first. Real-world finding worth surfacing to WP2.

## Schema-field rendering notes (feedback for the schema doc)
- `header.known_limitations_ref` is `KNOWN-LIMITATIONS.md` (controller module root)
  but in this repo the file lives at `docs/KNOWN-LIMITATIONS.md`. Rendered verbatim
  (R2). A cross-repo path that may want reconciling in the schema doc.
- `summary` carries only the four classification totals — no severity buckets. The
  `High+Critical` line is derived client-side by counting findings whose `severity`
  ∈ {High, Critical} (display-time counting over a documented field, not analysis).
