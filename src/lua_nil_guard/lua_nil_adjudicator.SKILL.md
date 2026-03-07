---
name: lua-nil-adjudicator
description: Strictly adjudicate whether a possibly nil value can reach a nil-sensitive Lua sink with explicit path evidence, strong false-positive control, and machine-readable verdicts. Use when reviewing Lua code for nil crash risk, validating candidate findings, or generating high-confidence remediation guidance.
skill_contract: lua-nil-adjudicator/v1
---

# Lua Nil Adjudicator

Use this skill when a candidate Lua sink has already been identified and the task is to decide whether `nil` is actually reachable at that sink.

## Goal

Produce a precise verdict with minimal false positives.

Judge only this question:

- Can `nil` reach the declared `nil-sensitive` sink on a real path supported by the provided code?

## Required Review Order

1. Identify the sink and the exact value expression under review.
2. Look for explicit safety evidence first.
3. If safety is not proven, trace the value origin and path to the sink.
4. Distinguish facts from inference.
5. Return `uncertain` when evidence is incomplete.

## Canonical Principles

- Unknown is not risk.
- Absence of proof is not proof of bug.

## Hard Rules

- Use only evidence from the target repository and declared facts, and cite `file:line` when possible.
- Do not assume undocumented business guarantees.
- Do not report risk without a concrete path explanation.
- Do not report safety without explicit supporting evidence.
- Return `uncertain` when evidence is incomplete.
- Treat runtime observations as supporting evidence, not absolute proof, unless the failing path is directly observed.

## Evidence Checklist

Check for these before calling a case risky:

- variable origin
- assignments and reassignments
- nearby guards such as `if x then`
- `assert(x)` style assertions
- defaulting patterns such as `x = x or ""`
- wrapper or normalizer functions
- function summaries and repository knowledge facts
- `@nil_guard` annotations on called functions (when verified consistent)

## Output Contract

Return a machine-readable object with:

- `status`: `safe`, `risky`, or `uncertain`
- `confidence`: `low`, `medium`, or `high`
- `risk_path`: only explicit, code-supported path steps
- `safety_evidence`: only explicit guards or contracts
- `missing_evidence`: what is still needed if unresolved
- `recommended_next_action`: one of `suppress`, `expand_context`, `verify_runtime`, `report`, `autofix`
- `suggested_fix`: only when a high-confidence, low-risk fix is clear

## Review Bias

- Prefer silence over speculative warnings.
- A sparse, trusted report is better than a noisy report.
- Default to `uncertain` instead of overstating risk.
