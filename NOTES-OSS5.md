# NOTES — OSS-5: StopContainer Generation Loss

Working branch: `feat/oss-5-stop-generation-loss` (off latest `main`, ce81716).

Status: **Phase 1 complete — paused for scope agreement before Phase 2 fix.**

---

## Phase 1 — Diagnosis (deliverable)

### 1. Repro (one command)

```
go test ./internal/sensor/ -run OSS5StopLoss -v
```

`internal/sensor/oss5_stop_loss_repro_test.go` drives the **real** `k8sResolver`
against a fake clientset and reproduces the loss deterministically:

- `PodPresent_Posts` — control: pod + RS present → resolves → would POST.
- `PodGCRace_DropsGeneration` — pod deleted before stop → `ResolveWorkload`
  404s → POST gate fails → generation dropped.
- `ReplicaSetGCRace_DropsGeneration` — RS reaped (scale-to-0 / rolling update),
  pod still Terminating → Pod→RS walk breaks → POST gate fails → generation dropped.

All three pass (loss reproduced). A live e2e variant for the Lima `k8s-dev` VM is
listed under Phase 2.

### 2. Loss boundary: **A — observed-but-never-sent (OSS / sensor)**

The generation dies on the sensor, before the POST, not in the controller.

**Boundary-level trace of a generation, StopContainer → persisted merged profile:**

| Boundary | Location | Behaviour | Verdict |
|----------|----------|-----------|---------|
| stop-hook entry | `internal/container/nri.go` `StopContainer` | `DenyCgroup` then `onStop` (synchronous) | reached |
| final snapshot | `cmd/sensor/main.go` `onContainerStop` → `agg.Snapshot()` | aggregator held by local ref; snapshot complete | reached, data intact |
| **POST gate** | `cmd/sensor/main.go:296` `r.resolver.ResolveWorkload(...)` | **live K8s GET Pod→RS→Deployment at stop time**; on `err != nil` or `dep==""` → `return` (no POST, no retry, no enqueue) | **DIES HERE** |
| POST send | `internal/sensor/post.go` `PostProfile` | only reached if the gate passes | n/a (skipped) |
| ingest / merge / persist | `neeva` `internal/controller/db/queries.go` `IngestProfile` | `profile_events` is INSERT-only; `container_coverage` upsert needs a POST | never invoked |

The controller side was checked and exonerated: `IngestProfile` only ever INSERTs
events (merge in `GetMergedManifest` is `GROUP BY path,source` with `SUM(count)`,
`MIN/MAX` times — additive, monotone). The only `DELETE FROM profile_events` is the
admin-only `DeleteSession`. So a generation that is never POSTed simply never
appears in `container_coverage` (written only inside `IngestProfile` when
`m.ContainerID != ""`) — exactly WP0-F's "pods never reached `container_coverage`".

**Root cause (one line):** the final POST is gated on a *live* `ResolveWorkload`
(three K8s GETs) performed at StopContainer time — i.e. during the pod/ReplicaSet
GC that the stop event itself triggers — and the deployment owner is resolved
lazily at stop, never cached at start, with no retry/enqueue. Any transient 404
on that path permanently drops the generation.

Note the asymmetry that makes this a latent bug: pod **namespace/name** *is* cached
at `CreateContainer` precisely because "NRI does not guarantee forwarding at stop
time" (nri.go:143) — but the **deployment owner** is *not* cached and must hit the
live API at the worst possible moment.

### 3. Owning repo: **OSS (`tracepod`)** — `cmd/sensor` + `internal/sensor`

The defect is the sensor's resolve-at-stop design. The task floated the
ReplicaSet-GC race under option B (controller); in this architecture the workload
resolution runs on the **sensor**, so the same race bites at boundary A. Fix lands
in OSS. (Controller `IngestProfile` is already additive/monotone; see the
monotone-merge property test proposed for Phase 2 to lock that invariant in.)

### 4. Blast radius

- **Trigger:** any stop that races pod/RS GC — pod delete, scale-to-0, rolling
  update, normal termination once the kubelet removes the pod. Intermittent
  (a race), which is why WP0-F "failed 3×" rather than always. Adopt-then-stop is
  not special; the WP0-F sequence simply stopped the pod promptly, tightening the
  race.
- **Magnitude:** the dropped POST is the **entire final generation**. For a
  single-generation workload (one long run, then stopped) that is the **whole
  profile** → merged profile silently empty/short → loaded files look not-loaded.
  This is the exact conservative-direction violation the gate philosophy forbids.
- **Partial masking:** the grace period sometimes lets the live GETs win the race,
  so the loss looks flaky rather than total. There is no periodic flush that masks
  it (the sensor only flushes on stop).
- **Secondary, independent loss (note, not the WP0-F cause):** `cmd/sensor/main.go`
  SIGTERM/SIGINT handler calls only `p.Close()` and exits — it does **not** flush
  live aggregators. A sensor restart/rollout/node-drain drops the in-flight
  generation of *every* currently-tracked container (could be the bulk for a
  long-running workload). Worth folding into the Phase-2 fix or flagging as a
  residual window.

---

## Phase 2 — Fix (proposed; not yet implemented — awaiting scope sign-off)

**Shape (boundary A):** resolve + cache the workload owner (deployment/statefulset)
and imageRef at container **start** (`onContainerStart`, when the pod and RS
reliably exist), keyed by container/cgroup alongside the existing podMeta cache.
The stop path then POSTs from cache with **no live K8s dependency** — the
generation's destination is fixed before the teardown window opens (mirrors the
OSS-4b ordering discipline on the detach side). Add a durable retry/no-op-on-empty
so a single POST hiccup can't drop a generation. Optionally: flush live aggregators
on SIGTERM to close the secondary window.

**Conservative-merge invariant test (controller, `neeva`):** property test that for
any sequence of generations (empty, out-of-order, duplicate), the merged observed
path set is non-decreasing — locks in the additive ingest so a regression can't
introduce a subtractive merge.

**Tests:** the repro automated as regression (sensor unit + Lima live e2e);
lifecycle matrix (adopt-then-stop, fresh-start-then-stop, rolling update,
scale-to-0, normal termination) each lands its final generation.

**Docs/CHANGELOG:** `docs/KNOWN-LIMITATIONS.md` + controller docs: the bug, the fix,
and any residual SIGKILL/no-graceful-stop truncation window (such profiles must be
treated as truncated → must not yield `not_affected` downstream).

### Open scope question (why paused)

Phase 2 likely touches **both** repos: the fix in OSS (sensor), and a
monotone-merge property test in `neeva` (controller). The task says to confirm
scope before implementing. Specifically: (a) cache-at-start in the sensor, (b)
SIGTERM flush yes/no, (c) add the controller-side monotone property test now or
defer. See the Phase-1 report message for the decision points.
