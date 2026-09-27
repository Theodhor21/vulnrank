# 1. Ports and adapters

- **Status:** accepted
- **Date:** 2026-09-25

## Context

vulnrank reads two scan formats, calls two external services (FIRST EPSS, CISA KEV) and
writes four output formats. More of each are likely: other scanners, a vendor threat-intel
feed, a DefectDojo export. The scoring rules are the part that must be correct and easy
to reason about, and they should not change when a format or an API does.

Tests must never touch the network, and the scoring logic should be testable with plain
objects instead of HTTP mocks or files.

## Decision

Structure the code as ports and adapters (hexagonal architecture):

- `domain/`: models and the P1–P4 rules. Pure functions, no I/O.
- `ports/`: `Protocol` interfaces the application needs: `FindingSource`,
  `ExploitProbability`, `KnownExploitedCatalog`, `Reporter`.
- `application/`: the use case (load, deduplicate, enrich, score, rank), written
  against the ports only.
- `adapters/`: one module per external format or service, each implementing a port.
- `cli.py`: the only place that knows concrete adapters and wires them together.

The dependency rule is enforced by `tests/test_architecture.py`, which parses every
module in `domain`, `ports` and `application` and fails on imports of adapters or of I/O
modules such as `os`, `pathlib`, `socket` or `http`.

## Consequences

- A new input or output format is one new adapter plus a line in `cli.py`; the core does
  not change. SARIF output (Phase 5) was added exactly this way.
- The scoring rules and the use case are tested with small in-memory fakes, which keeps
  those tests fast and focused.
- Adapters get their own contract tests (for example, the same scan in Trivy JSON and
  CycloneDX must yield identical findings).
- Cost: more files and indirection than a single script. For a tool this size the
  overhead is modest, and the enforced boundary is what keeps it modest over time.
