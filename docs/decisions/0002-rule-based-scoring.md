# 2. Rule-based scoring instead of an ML score

- **Status:** accepted
- **Date:** 2026-09-25

## Context

The tool must turn thousands of findings into a short list, and a security team has to
trust and act on that list. Two broad options:

1. A single learned or weighted score (for example, a model trained on exploitation
   data, or `a·EPSS + b·CVSS + c·criticality`).
2. A small set of explicit rules that assign priority tiers.

The main exploitation signal already exists as a model: EPSS is FIRST's machine-learning
estimate of exploitation probability, retrained and published daily. CISA KEV provides
ground truth for what is actually exploited.

## Decision

Use deterministic, ordered rules that place each finding in a tier (P1–P4), and record
every rule that fired as a human-readable reason. Tiers are checked from P1 down; the first
tier with a matching rule wins. Thresholds live in the config file with sensible
defaults. Within a tier, sort by EPSS, then CVSS, then fix availability.

The signals are ordered on purpose: confirmed exploitation (KEV) outranks predicted
exploitation (EPSS), which outranks theoretical severity (CVSS).

## Consequences

- **Explainable.** Every position comes with its reason, e.g. "in CISA KEV (added
  2023-10-10)". There is no score to reverse-engineer.
- **Deterministic and testable.** Each rule and each tier boundary has its own test; the
  same input always gives the same order.
- **Auditable policy.** Changing a threshold is a one-line config change that a reviewer
  can read, instead of retraining a model.
- **No training data needed**, and no second model duplicating what EPSS already does
  well. vulnrank uses EPSS rather than competing with it.
- Cost: tiers are coarse, and thresholds are judgement calls that may need tuning per
  organisation. For example, with the defaults an internet-exposed critical asset makes
  every CVE with EPSS ≥ 10% a P1, which can be a long list. The thresholds are
  configurable for this reason.
