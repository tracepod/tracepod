# Reachability quickstart

Most of the CVEs a scanner reports against a container image are for packages your
workload never actually loads. Tracepod profiles what your container *really*
touches at runtime, then tells you — per CVE — whether the affected package was
loaded during the profiling window. This is the **reachability report**, and it is
free.

This is a five-minute walkthrough: profile a workload, run `cve-report`, read the
summary.

## 1. Profile a workload

Install the sensor and exercise your workload so the sensor observes a
representative run (see the [README](../README.md) for the full install). Profiling
is passive — the sensor attaches eBPF kprobes and records the files your container
opens and the libraries it loads.

The longer and more representative the run, the more you can trust a `not_loaded`
verdict. A 30-second smoke test is not the same as an hour of real traffic.

## 2. Run `cve-report`

```bash
tracepod cve-report php-hello
```

```
Reachability report — acme-legacy/php-hello (profile 1)
  image  localhost:5000/tracepod-demo/php-hello@sha256:32afd47b…
  scan   grype 0.92.2 · server-side grype scan · generated 2026-01-02T00:00:01Z

759 findings: 132 loaded, 627 not loaded, 0 indeterminate, 0 unmatched
High+Critical — 97 findings: 35 loaded, 62 not loaded, 0 indeterminate, 0 unmatched

SEVERITY  CLASSIFICATION  CVE             PACKAGE      VERSION           EVIDENCE
Critical  loaded          CVE-2026-29167  apache2-bin  2.4.67-1~deb13u3  /usr/lib/apache2/modules/mod_authz_user.so (observed)
…

Showing 97 of 759 findings (severity ≥ high). Use --severity all to see every finding.

VEX export (not_affected attestations from not_loaded findings) is available in Tracepod Pro.

Reachability classifications are bounded by the profiling window. A package marked
not_loaded was not observed loading during the window — this is not proof of
unreachability. See KNOWN-LIMITATIONS.md for the observational-window caveat and
other limitations.
```

## 3. Read the summary

The headline is the two summary lines.

- **The raw total overstates the work.** `759 findings` sounds alarming, but a real
  `php:8.3-apache` image is dominated by low-severity noise. The honest number is
  the severity cut: of **97** High+Critical findings, only **35** were actually
  loaded. That — not 759, and not 132 — is the queue worth triaging first.
- The table **leads with that actionable slice** (High+Critical by default). Use
  `--severity all` to widen it, or `--severity critical` to narrow it.
- `loaded` is the column that matters: the affected package was observed in use.
  `not_loaded` means it was present but never seen loading during the window.

For the score behind the run (how well the window was observed) and the
attribution coverage, add `--verbose`.

## What this does — and does not — claim

The reachability report is an **observational** result. A `not_loaded` verdict
means *“not observed during this window,”* not *“unreachable.”* The footer says so,
verbatim, on every run — quote it, don’t round it off:

> Reachability classifications are bounded by the profiling window. A package
> marked not_loaded was not observed loading during the window — this is not proof
> of unreachability.

So treat `not_loaded` as **prioritisation**, not suppression. It tells you which
CVEs to look at last, not which to ignore.

> **A note on VEX.** This command shows the reachability *report*
> (loaded / not-loaded), which works on any sensor. Promoting `not_loaded` findings
> into a signed VEX `not_affected` statement is a separate, paid feature, and it
> requires a newer (schema-v3) sensor. On a current sensor everything gates
> conservatively — so read the report for what it is: an honest, observational map
> of which CVEs your workload actually exercises.

See the [`cve-report` CLI reference](cli-cve-report.md) for all flags and the
definitions of the four classifications.
