# 3. Drop-and-log error handling

- **Status:** accepted
- **Date:** 2026-09-25

## Context

Real inputs are messy. A scan of `python:3.8` has 11,706 vulnerability records. Scanner
output changes between versions, CycloneDX documents from different tools fill fields
differently, and the EPSS and KEV services can be slow, rate-limited or down. If one
malformed record, or one failed HTTP request, aborted the run, the tool would be useless
in CI exactly when it is needed.

Silently ignoring problems is not acceptable either: a missing finding or a missing KEV
flag changes the priority list.

## Decision

Distinguish two kinds of failure:

- **The input as a whole is unusable** (file missing, not JSON, not a supported format,
  invalid config). Stop with a clear message and exit code 2.
- **One record or one lookup fails.** Log a warning that says exactly what and where
  (for example, `Results[1].Vulnerabilities[3]: PkgName: Field required`), skip it, and
  carry on.

For enrichment, degrade step by step: fresh cache, then the API, then stale cache, then
no data for that signal, with a warning at each fallback. Offline mode uses only the
cache and local files. Logs go to stderr so stdout carries only the report.

## Consequences

- One bad record costs one finding, not the whole run, and the warning makes the loss
  visible.
- CI pipelines keep working through transient EPSS or KEV outages.
- Every drop path has a test that checks both the skip and the warning text.
- Cost: a run can succeed with less information than expected. When a lookup fails and
  nothing is cached, a CVE is ranked without that signal; for KEV this means "not in KEV".
  The warning on stderr is the only signal, so CI users should not suppress stderr, and
  `--quiet` should be used with care.
