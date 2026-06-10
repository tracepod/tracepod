# Recorded profile fixtures — schema v2

Recorded by hack/record-profile-fixtures.sh on 2026-06-10T06:43:01Z
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

Note: container IDs differ on every re-record; the marker outcomes above and the
pinned images are the stable, replay-relevant properties.
