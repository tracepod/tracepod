# Profile fixtures

Recorded sensor profile documents, captured **verbatim** from a live sensor run,
organised by schema version:

```
testdata/profile-fixtures/
  v3/
    static.json           # fast-saturating static binary — process_start_observed: true, event_loss.total: 0
    interp.json           # interpreted app (python) — true, event_loss.total: 0
    restart.json          # restarted in-window (one file per generation, -N suffixed) — true, event_loss.total: 0
    missed-start.json     # deployed before the sensor, adopted via Synchronize — false, event_loss.total: 0
    induced-loss.json     # high-churn workload under a shrunken (4 KB) ring buffer — event_loss.total > 0
    RECORDING.md          # provenance: when, which workloads/digests
```

Fixtures are named by the workload they came from, not the container ID
(container IDs differ on every re-record). `fx-restart` produces several
profiles (one per container lifecycle); the second and later generations are
suffixed `-2`, `-3`, … Collection filters the sensor's output down to just these
workloads' containers — the sensor also profiles system pods, which are
excluded.

The **induced-loss** fixture is the stable proof that `event_loss.total > 0` is
reachable and recorded (schema v3). It is captured from a real run under a
deliberately tiny ring buffer (`--ringbuf-bytes`) and a file-open storm — like
every fixture, recorded verbatim, never hand-edited. Every *other* fixture is
recorded under the default buffer and reads `event_loss.total: 0` (a true zero).

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

The recorder brings up kind + the sensor and profiles these representative
workloads:

| Name | Shape | Why |
|------|-------|-----|
| `fx-static` | fast-saturating static Go binary | minimal, quickly-complete file surface |
| `fx-interp` | interpreted app (python) | large shared-library surface opened at import |
| `fx-restart` | exits and is restarted during the window | exercises restart / start-event records |
| `fx-missed` | deployed before the sensor | adopted via NRI `Synchronize` — `process_start_observed: false` |
| `fx-induced` | file-open storm under a 4 KB ring buffer | overflows the buffer so `event_loss.total > 0` (schema v3) |

`fx-restart` produces several profiles (one per container lifecycle), letting a
consumer verify restart counting by summing `container_starts` across them.

`fx-induced` runs in a dedicated final phase: the sensor is re-deployed with a
shrunken ring buffer (`sensor.ringbufBytes` / `--ringbuf-bytes`), the storm
workload forces `bpf_ringbuf_reserve()` failures, and the resulting profile —
the only one with nonzero `event_loss` — is captured as `induced-loss.json`.
