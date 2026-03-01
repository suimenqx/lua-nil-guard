# Prompting Guide

## Purpose

This document defines the baseline prompt contract for all agent adjudication in this repository.

The prompt must enforce:

- evidence-first reasoning
- explicit separation of facts and inference
- no speculative bug claims
- `uncertain` as the default for incomplete proof

## Hard Constraints

Every adjudication prompt must include these exact principles:

- `Unknown is not risk.`
- `Absence of proof is not proof of bug.`

## Required Inputs

- Target case metadata
- Sink rule metadata
- Local context
- Static reasoning summary
- Function summaries
- Repository knowledge facts

## Required Outputs

- `status`
- `confidence`
- `risk_path`
- `safety_evidence`
- `missing_evidence`
- `recommended_next_action`
- `suggested_fix` when confidence is high enough
