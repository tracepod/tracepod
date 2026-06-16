# Removal Manifest Schema

The **removal manifest** is the JSON the hardener produces for one hardened
build. It is written to `<output-dir>/removal-manifest.json` on **every
successful harden**, travelling through the same output directory as the SBOMs.

It is a **set-difference fact**: every OS package present in the source image and
**entirely absent** from the hardened image, with the source-image file paths
that drove each removal. It is the OSS-3 **producer** for the removal-VEX
contract; the controller (WP3) **consumes** it to emit `component_not_present`
attestations for the hardened image without ever re-scanning it.

This directory holds the formal JSON Schema for each published version:

| File | `schema_version` | Status |
|------|------------------|--------|
| [`v1.schema.json`](v1.schema.json) | string `"1.0"` | **current** |

## What this manifest is — and is not

- **Facts only.** The manifest states a set-difference: a package whose owned
  files are all absent from the hardened image. It carries **no** reachability,
  runtime, justification, or VEX vocabulary. The consumer decides what the
  removal *means*.
- **No CVE / findings source.** CVE↔package association is the controller's
  concern — it owns the findings source and joins it to this removed-set when it
  generates removal VEX. There is deliberately **no scanner/findings field** in
  this manifest, and the hardener runs **no vulnerability scanner**. (See
  _Contract & cross-repo_ below.)
- **Product identity is the hardened image, by digest.**

## The R2 rule: partial retention is not removal

A package is listed as removed **iff none of its owned files are retained** in
the hardened image. Consequences:

- A package with **any** retained file is **absent** from the manifest —
  partially-retained ≠ removed. Listing it would be a false absence claim, since
  some of its content still ships.
- **Multi-owner files** fall out of this naturally: if a file owned by several
  packages is retained, **every** package owning it is treated as retained.
- A package with **zero owned files** is skipped: with no file evidence there is
  nothing to prove absent. In practice this means only file-owning **OS
  packages** (dpkg/apk/rpm) appear; language-ecosystem packages syft catalogs
  without an owned-file list never do. The hardened image is `FROM scratch` and
  carries no package database, so package presence can only be asserted through
  file presence — which is exactly what this manifest does.

## How it is derived

1. The hardener extracts the **full source filesystem** (all layers) of the
   pinned source digest into a staging tree — the same tree the build consumes.
2. `syft` scans **that staging tree** (`dir:<staging>`, `syft-json`), yielding
   each package's purl + the absolute paths it owns. Scanning the already-pulled
   tree (not a re-pull or tag re-resolve) guarantees the package view and the
   retained file view are provably of **one image**.
3. The retained set is the finalised manifest file set (post ELF resolution,
   scratch-compat, includes/ensures, and symlink-target expansion) — i.e. the
   true hardened-image contents.
4. `removed = { p ∈ source-packages : owned(p) ∩ retained = ∅ }`, with evidence
   paths sorted and de-duplicated, output sorted by purl.

No analysis the pipeline has not already performed is re-run beyond the source
package catalog: the removed-set is serialised existing knowledge.

## Field reference

| Field | Type | Notes |
|-------|------|-------|
| `schema` | string const `tracepod.dev/removal-manifest` | Contract identity (shared with the controller). |
| `schema_version` | string const `"1.0"` | Bumped in lockstep with a new schema file. |
| `source_digest` | string | `sha256:…` of the source image the build consumed. |
| `source_platform` | string | e.g. `linux/arm64`. Additive audit metadata; arch is also in each purl qualifier. |
| `hardened_digest` | string (required) | `sha256:…` of the hardened image — product identity. |
| `hardened_ref` | string | `repo[:tag]@digest` of the hardened image. |
| `tooling.hardener` | string | Hardener version (`dev`/`unknown` in unreleased builds). |
| `tooling.syft` | string | Syft version from the syft-json descriptor. |
| `removed[]` | array | One entry per removed package. Empty when nothing was removed. |
| `removed[].purl` | string (required) | package-url, verbatim from the source SBOM. |
| `removed[].name` | string | Package name. |
| `removed[].version` | string | Package version. |
| `removed[].paths[]` | array of string | Owned source-image paths whose absence proves removal (evidence, sorted/unique). |

### Consumed subset vs additive metadata

The fields the controller deserialises (the **contract**) are: `schema`,
`schema_version`, `source_digest`, `hardened_digest`, `hardened_ref`, and
`removed[]`. `source_platform` and `tooling` are **additive** OSS-3 audit
metadata the controller ignores; they never affect removal VEX.

## Versioning policy

Mirrors the [profile schema](../profile-schema/README.md) policy:

1. Every manifest carries `schema` + `schema_version` (the string `"1.0"`).
2. The hardener only ever emits the current version.
3. **Any change to the wire shape requires a version bump**: add a new
   `docs/removal-manifest-schema/v<N>.schema.json` (do **not** edit a published
   one — they are immutable), record its hash in the schema-drift guard
   (`hardener/removal_schema_drift_test.go`), update this table + field
   reference, add a CHANGELOG entry, and **bump the contract constant in lockstep
   with the controller** (`RemovalManifestSchemaVersion`). The schema is the only
   shared artifact between the two repos — a unilateral shape change silently
   breaks removal VEX.
4. Published schemas are frozen; the drift test fails on any in-place edit, and
   the conformance test validates every emitted manifest against the current
   schema with `additionalProperties: false`.

## Contract & cross-repo

The shape here matches the controller's `RemovalManifest` reader (WP3). The
controller never re-derives the removed-set by re-scanning the hardened image —
that would create a second source of truth. Until a hardener release carrying
this manifest is deployed, the controller's removal-VEX generator no-ops (no
document, no error); when the manifest appears it activates with no controller
change.

> **Follow-up (controller, separate session): retire the findings bridge.** WP3
> ships a temporary bridge that reconstructs the removed-set context from the
> latest completed reachability run for the same digest. Once this manifest is
> produced, the controller should read the removed-set from the manifest and drop
> the bridge, keeping CVE association on its own findings source. That is a
> controller-repo change; this repo only produces the manifest.

## Consumer guidance

- **Treat an absent manifest as "no removed-set"**, not an error — pre-OSS-3
  builds and tool-unavailable builds won't have one.
- **Treat an empty `removed`** the same as a valid build that stripped nothing.
- **Do not infer CVEs from this document.** Join `removed[].purl` to your own
  findings source.
