# Profile fixtures

Recorded sensor profile documents, captured **verbatim** from a live sensor run,
organised by schema version:

```
testdata/profile-fixtures/
  v2/
    static.json           # fast-saturating static binary — process_start_observed: true
    interp.json           # interpreted app (python) — true
    restart.json          # restarted in-window (one file per generation, -N suffixed) — true
    missed-start.json     # deployed before the sensor, adopted via Synchronize — false
    RECORDING.md          # provenance: when, which workloads/digests
```

Fixtures are named by the workload they came from, not the container ID
(container IDs differ on every re-record). `fx-restart` produces several
profiles (one per container lifecycle); the second and later generations are
suffixed `-2`, `-3`, … Collection filters the sensor's output down to just these
four workloads' containers — the sensor also profiles system pods, which are
excluded.

These exist to power the **controller repo's CI replay path** — they are copied
into the private controller repo so its coverage-scoring tests run against real
sensor output, not synthetic data.

## Rules

- **Recorded artifacts only.** Never hand-edit a `*.json` fixture. To change
  them, re-record (below). CI may diff them; a hand-edit is a bug.
- **Deterministic.** Workloads are pinned by image **digest** (not tag) so a
  re-record reproduces the same library/file surface.
- **Validated.** Every committed fixture is validated against the matching
  `docs/profile-schema/v<N>.schema.json` by `TestProfileFixtures_conform`
  (manifest package) in the standard test job.

## Recording

Locally, inside the `k8s-dev` Lima VM:

```bash
make record-fixtures
# or directly:
limactl shell k8s-dev -- bash -c 'cd <repo> && bash hack/record-profile-fixtures.sh'
```

In CI, trigger the **Record profile fixtures** workflow
(`.github/workflows/record-fixtures.yaml`) via `workflow_dispatch`. It re-records
and opens a PR — fixtures change deliberately, never implicitly.

The recorder brings up kind + the sensor and profiles three representative
workloads:

| Name | Shape | Why |
|------|-------|-----|
| `fx-static` | fast-saturating static Go binary | minimal, quickly-complete file surface |
| `fx-interp` | interpreted app (python) | large shared-library surface opened at import |
| `fx-restart` | exits and is restarted during the window | exercises restart / start-event records |

`fx-restart` produces several profiles (one per container lifecycle), letting a
consumer verify restart counting by summing `container_starts` across them.
