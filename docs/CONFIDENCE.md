# Confidence Scoring Reference

The `harden build` command prints a confidence score for every image it produces:

```
Confidence:  76/100 (Medium) — 3 manual entries indicate paths not observed during profiling; profile duration 6s is below the recommended minimum of 10m0s
```

This document explains what the score means, how to improve it, and when it is safe to ship an image that scores below 100.

---

## What the confidence score means

The confidence score is a **coverage signal**, not a quality grade.

A score of **100** means every known sensor coverage gap was actively mitigated during the profiling session: the window was long enough, all startup-phase paths were captured (e.g. via a reload trigger), and every path in the manifest was directly observed by the eBPF sensor rather than manually added.

A score **below 100** does not mean the image is broken or unsafe to deploy. It means specific gaps remain open — and the score tells you exactly which ones and what would close them.

The right mental model: the confidence score answers the question *"how representative was my profiling session?"*. Profile your application under realistic production load and your score will be high. Profile it while it sits idle and you will need to fill gaps manually, which reduces the score.

---

## Score levels

| Score | Level | What it means in practice |
|-------|-------|--------------------------|
| 80–100 | **High** | Profiling window was representative; all common gaps were mitigated. Safe to promote to production with normal change-management process. |
| 60–79 | **Medium** | One or two gaps remain open. Review the penalty reasons — they tell you exactly what to fix before the next profiling run. Acceptable for staging; review before production. |
| 40–59 | **Low** | Several gaps are open, or a significant number of manual entries were required. Verify the image starts and serves traffic before promoting. |
| 0–39 | **Very Low** | The profile is incomplete or nearly empty. The hardener emits an additional `Warning:` line. Do not promote to production without a new profiling run. |

---

## Signals and penalties

The score starts at 100 and penalties are subtracted for each signal detected.

> **Note on calibration:** The penalty weights below are v1 defaults, calibrated against the `nginx:1.25-alpine` reference profile. They will be adjusted before the GA release once real-world profiling data is available. Do not hard-code specific score thresholds in external workflows or automation until after GA — the weights may change in a patch release.

### Empty profile (−60)

**Trigger:** The manifest contains zero `direct` entries — no file opens were observed by the eBPF sensor.

**What this means:** The sensor was either not running, the container was idle for the entire profiling window, or the container completed before profiling began.

**Fix:** Run the sensor while the container is handling real or synthetic traffic. Verify the sensor is attached to the correct cgroup before starting the container.

---

### Zero-duration profile (−20)

**Trigger:** `profile_start` equals `profile_end` in the manifest — no time elapsed during profiling.

**What this means:** The manifest may have been generated programmatically rather than from a real profiling run, or the container exited immediately.

**Fix:** Verify the sensor wrote a valid profiling window. Check `profile_start` and `profile_end` in the manifest JSON.

---

### Short profile window (−4 to −20)

**Trigger:** The actual profiling duration is below the recommended minimum (default: 10 minutes). The penalty scales with how far below the minimum the window was:

| Actual window | Penalty |
|---------------|---------|
| ≥ 75% of minimum | −4 |
| 50–74% of minimum | −8 |
| 25–49% of minimum | −14 |
| < 25% of minimum | −20 |

**What this means:** A short profiling window may miss infrequently-accessed files — error pages, health-check endpoints, batch code paths, or files opened only after a certain number of requests.

**Fix:** Profile for at least 10 minutes (the default minimum). Pass `--min-profile-duration 30m` if your application has longer idle cycles or infrequent code paths. The minimum duration should match the longest expected access interval for any file in your image.

**CI / test harnesses:** If your harness intentionally uses a short profiling window (e.g. 30-second smoke runs), pass `--min-profile-duration` equal to the actual window so confidence is evaluated relative to the test budget rather than the production recommendation. For example: `--min-profile-duration 30s`. Clean images scored against their own window show 100/100; images requiring manual entries still score lower regardless of window length.

---

### Manual entries (−5 per entry, capped at −25)

**Trigger:** The manifest contains `source: "manual"` entries that were not added by the hardener itself (i.e. `included_because` is not exactly `"scratch-compat"`).

**What this means:** Each manual entry represents a path that the eBPF sensor did not observe during profiling. You added it because you knew it was needed — but the sensor didn't see it. This is a coverage gap.

**Fix:** Profile under conditions that exercise these paths:
- For startup-race paths: trigger a process reload during profiling
- For static content: send HTTP requests to those paths during profiling
- For dlopen paths: exercise the code paths that load those libraries

**Note:** Scratch-compatibility entries (`/etc/passwd`, `/etc/group`, dynamic linker, TLS certs) are added automatically by the hardener and are **not** penalised — they are structural necessities, not coverage gaps.

---

### Startup-race entries (−3 per entry, capped at −12, stacks with manual)

**Trigger:** Manual entries whose `included_because` field contains the substring `"startup-race"`.

**What this means:** These paths were opened by the application's master process before the NRI `StartContainer` hook fired — before the sensor's cgroup filter was active. They are invisible to the sensor no matter how long you profile. See [KNOWN-LIMITATIONS.md §1](KNOWN-LIMITATIONS.md#1-nri-startup-race) for the full explanation.

**Fix:** Trigger a process reload during the profiling window. For nginx:

```bash
sudo crictl exec $CTR nginx -s reload
```

This causes the worker processes to re-exec, generating new `execve` events while the cgroup is registered. The startup-race paths themselves (pid file, log dirs) still need to be in the manifest manually, but the sensor will at least observe the nginx binary via execve — reducing the gap.

---

### Undocumented manual entries (−3 per entry, capped at −9)

**Trigger:** Manual entries with an empty `included_because` field.

**What this means:** You added a path to the manifest but didn't document why. The reason matters: it propagates to the SBOM (`included_because` is carried through to the CycloneDX/SPDX output), giving auditors full traceability. An undocumented entry cannot be audited.

**Fix:** Add an `included_because` value to every manual entry:

```json
"/run/nginx.pid": {
  "source": "manual",
  "access_modes": ["w"],
  "included_because": "startup-race: pid file written by nginx master before cgroup registration"
}
```

---

## How to reach 100/100

The following checklist describes a profiling session that would score 100 on a typical web server image:

1. **Profile for at least 10 minutes** (or `--min-profile-duration` if set longer).
2. **Trigger a process reload** during profiling for process-model servers (nginx, apache, etc.) — this captures the binary via `execve`.
3. **Send HTTP requests** to every content type and endpoint during profiling — this captures static files that are only opened on request.
4. **Exercise all code paths** that use `dlopen()` during profiling — the sensor captures `mmap(PROT_EXEC)` events so dynamically-loaded libraries appear as `source: "direct"`.
5. **Add manual entries only when strictly necessary** — prefer improving profiling coverage over adding manual entries.
6. **Document every manual entry** with an `included_because` value explaining why the sensor couldn't observe it.
7. **Verify the image starts** with `nginx -t` (or equivalent) before promoting.

---

## When to ship below 100

A lower score is not a blocker if you understand which gaps remain and have verified the image works.

**Example:** An nginx image scores 76/100 — it has 3 startup-race manual entries (the pid file and log directories) and the profiling window was 8 minutes instead of 10. The image passed `nginx -t` and served `HTTP 200` in the e2e test. You know the startup-race entries are correct because you reviewed them against the [known-limitations runbook](KNOWN-LIMITATIONS.md). This is a safe deployment.

The score exists to surface gaps, not to block deployments. Use it as a checklist for improving your next profiling run.

---

## `--verbose` output

Pass `--verbose` to `harden build` to see the full penalty breakdown and any ELF audit notes:

```
Confidence:  76/100 (Medium) — 3 manual entries indicate paths not observed during profiling; ...
             Penalty breakdown:
               manual-entries (-15): 3 manual entries indicate paths not observed during profiling
               startup-race (-9): 3 startup-race entries — NRI hook fired after application opened files the sensor could not observe
             Audit: 2 inferred-elf entries whose parent binary has no direct entry (expected if dynamic linker opened the library):
               /lib/ld-musl-aarch64.so.1
               /lib/libpcre.so.1
```

The **audit** note (orphan inferred-elf) is informational only and does not affect the score. It appears when an inferred-elf entry's parent binary has no direct observation — which is expected when the dynamic linker itself opens the library rather than the application. No action required unless you see a library name you don't recognise.

---

## Relationship to KNOWN-LIMITATIONS.md

The confidence score is the quantified form of the three sensor coverage gaps documented in [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md):

| Gap | Confidence signal |
|-----|------------------|
| [NRI startup race](KNOWN-LIMITATIONS.md#1-nri-startup-race) | `startup-race` penalty on manual entries with `"startup-race"` in `included_because` |
| [Static content not accessed](KNOWN-LIMITATIONS.md#2-static-content-not-accessed-during-profiling) | `manual-entries` penalty on any manual entry added because no HTTP requests were made |
| [dlopen on uninvoked paths](KNOWN-LIMITATIONS.md#3-dlopen-on-uninvoked-code-paths) | `manual-entries` penalty on any manual entry added for a dlopen'd library not exercised during profiling |

All three gaps have the same root cause — incomplete profiling window coverage — and the same answer: profile under representative load.

---

## Directory inclusion (`--include`)

The `--include` flag is the escape hatch for paths the sensor cannot observe regardless of profiling hygiene:

```bash
harden build \
  --manifest profiles/<container-id>/files.json \
  --source nginx:1.25-alpine \
  --output /tmp/nginx-hardened \
  --include /usr/share/nginx/html \
  --include /etc/nginx/conf.d
```

Every regular file and file symlink found under the specified directory in the source image layers is added to the manifest with `source: "directory-inclusion"`. Directory symlinks are not descended into (WalkDir does not follow them) but appear as single entries. These entries are visible in the `Files:` output line:

```
Files:       60 (37 direct, 4 inferred-elf, 9 manual/scratch-compat, 10 directory-inclusion)
```

Directory-inclusion entries are **not** penalised by the confidence scorer — they are an explicit operator choice, not a sensor coverage gap. Use `--include` for:

- **Static web content directories** where you cannot send synthetic requests during profiling
- **Plugin directories** for dlopen'd libraries that are always present but conditionally loaded
- **Configuration directories** that are read at startup before the NRI hook fires

If a path specified via `--include` is not found in the source image layers (because it is created at runtime, not baked into the image), the hardener emits a warning:

```
Warning:     --include /var/log/nginx/: not found in source image (directory may be created at runtime)
```

This is non-fatal — the path is simply not added to the manifest.
