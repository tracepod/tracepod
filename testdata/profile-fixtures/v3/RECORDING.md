# Recorded profile fixtures — schema v3

Recorded by hack/record-profile-fixtures.sh on 2026-06-11T19:53:15Z
(arch: aarch64). Verbatim sensor output — do not edit by hand; re-record instead.

Workloads (pinned by digest):
- static (whoami):  traefik/whoami@sha256:1699d99cb4b9acc17f74ca670b3d8d0b7ba27c948b3445f0593b58ebece92f04
- interp (python):  python@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
- restart/missed (busybox): busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662

Fixtures (one profile per profiled container; restart generations suffixed -N):
- static.json       fast-saturating static binary — process_start_observed: true
- interp.json       interpreted app, large shared-library surface — true
- restart*.json     restarted in-window; each generation a separate profile — true
- missed-start.json deployed BEFORE the sensor, adopted via Synchronize — false
- induced-loss.json high-churn workload under a 4096-byte ring
                    buffer — schema-v3 event_loss.total > 0 (the rest read 0)

Event-loss (schema v3 + OSS-4b): every fixture carries event_loss with a HARD
gate (total = Σ by_stage) and a separately-gated TOLERATED category
(event_loss.tolerated.path_read_failed). Normal fixtures read total: 0 with a
path_read_failed idle floor (typically 0-2 — visible, never folded into total);
induced-loss reads total > 0.

Note: container IDs differ on every re-record; the marker/loss outcomes above and
the pinned images are the stable, replay-relevant properties.
