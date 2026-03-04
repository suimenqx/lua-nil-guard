# Lua-Nil-Review-Agent Execution Plan

> Decision baseline for the next major project phase. This document converts the current expert-agent consensus into an execution plan with entry criteria, boundaries, metrics, and review checkpoints.

## 1. Mission

Build an industrial-grade Lua nil-risk review system that prioritizes precision over recall by moving core proof generation from regex-like local heuristics toward AST-backed static reasoning, while keeping LLMs in a judge/explainer role instead of a primary inference role.

## 2. Locked Strategic Decisions

These decisions are considered settled unless new evidence forces a revision:

1. `Precision > Recall` remains the governing product principle.
2. The next major milestone is AST-driven static analysis, not broader prompt engineering.
3. LLMs remain downstream:
   - audit `StaticProof`
   - explain verdicts
   - arbitrate uncertainty
   They should not become the main source of control-flow inference.
4. The dominant current source of avoidable `unknown_static` is field-path reasoning, especially table field chains.
5. Cross-file analysis must remain lightweight, bounded, and deterministic.
6. Automatic contract discovery may produce drafts only; it must not directly mutate authoritative contracts.

## 3. Immediate Objective

Start a controlled AST migration of `static_analysis.py` with the narrowest high-value scope:

- replace the most fragile guard-detection logic first
- preserve a fallback to legacy behavior during migration
- measure precision and performance before widening scope

This is a guard-first migration, not a full static analysis rewrite.

## 4. Non-Goals For The Immediate Phase

The following are explicitly out of scope for the first AST migration cycle:

1. Full module-wide AST rewrite.
2. Cross-file AST inlining.
3. Complex origin/source-chain relocation logic.
4. Generalized table shape inference.
5. Broad Few-Shot prompt expansion.
6. Any unbounded interprocedural analysis.

## 5. Roadmap

### Phase 1: AST Guard-First Migration

#### 1.1 Deliverable

Introduce a production-safe AST-backed guard analysis path in `static_analysis.py` that can coexist with the current legacy path.

#### 1.2 Scope

The first AST implementation must focus on guard recognition only:

1. `if x then ... end`
2. `if not x then return end`
3. `assert(x)` and similar explicit guard exits
4. guard visibility through nested `do ... end`
5. locating the enclosing `if_statement`, `do_block`, and function boundary for a candidate

Source origin relocation is intentionally deferred until after the first AST phase proves stable.

#### 1.3 Implementation Strategy

1. Add an AST helper layer in `static_analysis.py` that:
   - resolves the syntax node nearest `CandidateCase.line/column`
   - walks ancestor nodes
   - identifies enclosing control-flow constructs
2. Prefer Tree-sitter Query (`.scm`) based matching for key node classes:
   - `if_statement`
   - `do_block`
   - function definitions
3. Use the AST path only to produce proofs when the reasoning is explicit and bounded.
4. If the AST path cannot prove the case safely, return either:
   - a structured fallback to the legacy path, or
   - a structured unknown result

#### 1.4 Fallback Strategy

During migration, verdict production must explicitly distinguish:

1. `ast_primary`
   - AST path handled the case and produced the decision-driving proof.
2. `ast_fallback_to_legacy`
   - AST path ran but could not safely complete, so the legacy logic was used.
3. `legacy_only`
   - AST path was unavailable or skipped.

This traceability is required for trustworthy rollout and later deprecation of the legacy path.

These states must be observable in benchmark output so the team can measure not only verdict quality, but also how much real analysis has migrated off the legacy path.

#### 1.5 Structured Unknowns

Any AST limitation discovered in this phase must be recorded as a structured reason, not flattened into a generic unknown.

Initial `unknown_reason` categories should include at least:

1. `unsupported_control_flow`
2. `dynamic_metatable`
3. `upvalue_capture`
4. `dynamic_index_expression`
5. `unresolved_ast_node`

The short-term rule is simple: if the system cannot safely model it, it stays conservative, but it must say why.

`unknown_reason` must propagate through the same structured review pipeline used for other evidence:

1. local static result
2. evidence packet
3. downstream adjudication context when relevant

#### 1.6 Benchmark Requirement

Phase 1 requires a dual benchmark strategy:

1. Baseline suite:
   - `examples/mvp_cases/semantic_suite`
   - must show no regression in proven safe/risky cases
2. Stress suite:
   - add new targeted cases for:
     - 7+ nested `if/else`
     - loops with `break` and `return`
     - variable shadowing across `do ... end`
     - nested branch patterns that currently challenge text-based logic

The stress suite exists to prove AST value where regex-like logic is weakest.

#### 1.7 Acceptance Criteria

Phase 1 is considered successful only if all conditions hold:

1. No new deterministic false positives are introduced in `semantic_suite`.
2. Existing high-confidence safe/risky benchmark cases do not regress.
3. AST path reduces ambiguity or increases stability on stress-suite cases.
4. Runtime overhead remains controlled:
   - moderate slowdown is acceptable
   - order-of-magnitude regressions are not
5. All AST-derived outcomes remain explainable through `StaticProof`.

#### 1.8 Exit Gate

Only after Phase 1 passes do we expand AST coverage to:

1. `elseif`
2. `repeat-until`
3. richer block reachability
4. local origin/source positioning

### Phase 2: Field-Path Tracking

#### 2.1 Objective

Reduce `unknown_static` caused by table field chains by making field paths a first-class static concept.

#### 2.2 Foundation

Unify the existing path-related contract concepts into one reusable internal path model:

1. `required_arg_roots`
2. `required_arg_prefixes`
3. `required_arg_access_paths`

#### 2.3 First Supported Patterns

1. `local x = req.params.user`
2. `if user.profile then ...`
3. `local id = user.profile.id or ''`
4. `req.headers["x-token"]` canonicalized into a stable path form

Dynamic keys such as `req.params[token]` remain conservative unless explicitly modeled later.

#### 2.4 Acceptance Criteria

1. Field-path cases that are currently ambiguous become provably safe or clearly risky more often.
2. Canonical path matching remains deterministic.
3. Dynamic indexes do not accidentally gain false certainty.

### Phase 3: Lightweight Cross-File AST Inlining

#### 3.1 Objective

Use bounded, deterministic single-hop AST inlining to reason about small helper functions without escalating to general interprocedural analysis.

#### 3.2 Allowed Targets

Only inline functions that are:

1. module-qualified and resolvable
2. short and syntactically simple
3. side-effect-light
4. recognizable as:
   - guard helpers
   - transparent wrappers
   - defaulting wrappers

#### 3.3 Hard Limits

1. Single hop only
2. Bounded depth only
3. No recursive fixed-point analysis
4. No whole-program call graph solving

#### 3.4 Acceptance Criteria

1. Cross-file helper wrappers reduce false positives in bounded cases.
2. Complexity remains operationally predictable.
3. Proofs remain compact and explainable.

### Phase 4: Targeted LLM Enhancement

#### 4.1 Objective

Improve LLM consistency by teaching it to judge structured proofs rather than infer raw control flow from scratch.

#### 4.2 Scope

Few-Shot examples should be keyed to:

1. `StaticProof.kind`
2. `StaticProof.depth`
3. `VerificationSummary`
4. structured `unknown_reason`

#### 4.3 Role Design

1. Prosecutor:
   - tries to invalidate the static proof chain
   - finds unguarded reachable paths
2. Defender:
   - argues only from guard, contract, wrapper, and proof evidence
3. Judge:
   - decides sufficiency of proof, not theoretical possibility

### Phase 5: Data Flywheel

#### 5.1 Contract Discovery

Allow LLM-assisted discovery to produce contract drafts for review, never automatic production contracts.

#### 5.2 Medium/Uncertain Feedback Loop

Use review outcomes from `medium` and `uncertain` cases to generate:

1. new AST patterns
2. new wrapper recognizers
3. new contract proposals

This phase must refine precision, not widen silent assumptions.

## 6. Operational Rules During Execution

1. Every new proof-producing feature must emit structured rationale.
2. Every unsupported construct encountered in AST mode must emit an `unknown_reason`.
3. New syntax support must arrive behind measurable benchmark coverage.
4. A new feature that improves recall but measurably harms precision is rejected.
5. The legacy path cannot be removed until AST coverage data proves replacement readiness.

## 7. Risks And Mitigations

### Risk 1: AST Phase Bloats In Scope

Mitigation:

1. Keep Phase 1 guard-only.
2. Explicitly defer origin relocation.
3. Require phase exit gates before widening scope.

### Risk 2: Precision Regresses During Migration

Mitigation:

1. Dual benchmark gate.
2. Structured fallback.
3. Conservative unknown behavior for unsupported constructs.

### Risk 3: AST Adds Complexity Without Sufficient Value

Mitigation:

1. Stress-suite proof of value is mandatory.
2. Require explainable proof output, not opaque improvements.
3. Stop expansion if ambiguity does not materially improve.

### Risk 4: Future LLM Work Pulls The Project Off Course

Mitigation:

1. Defer generalized prompt expansion.
2. Limit LLM changes to proof judgment and explanation.
3. Keep proof production static-first.

## 8. Immediate Next Actions

The next concrete work sequence should be:

1. Define Phase 1 benchmark harness:
   - lock `semantic_suite`
   - add a new stress suite for deep branching and shadowing
2. Add AST/query scaffolding:
   - introduce `.scm` query files for control-flow nodes
   - build node lookup helpers
3. Implement guard-first AST proofing:
   - replace only guard detection in the first pass
4. Add `unknown_reason` plumbing:
   - preserve conservative behavior
   - expose unsupported dynamic constructs explicitly
5. Add migration observability:
   - expose `ast_primary` / `ast_fallback_to_legacy` / `legacy_only` counts in benchmark reporting
6. Run comparative benchmark:
   - compare legacy vs AST-primary vs fallback cases
7. Decide whether to widen AST coverage based on measured results

## 9. Plan Review Pass 1

Review focus: scope discipline.

Findings:

1. The original strategy risked becoming a broad AST rewrite too early.
2. The plan is now correctly narrowed to guard-first AST migration.
3. Origin relocation is explicitly deferred until after Phase 1 stabilizes.

Adjustment locked in:

- Phase 1 remains guard-only.

## 10. Plan Review Pass 2

Review focus: rollout safety and observability.

Findings:

1. A direct AST switchover would hide regressions.
2. The system needs visibility into when AST succeeded versus when legacy logic still carried the result.
3. Generic `unknown_static` would hide the most valuable next improvements.

Adjustments locked in:

1. Structured fallback states:
   - `ast_primary`
   - `ast_fallback_to_legacy`
   - `legacy_only`
2. Structured `unknown_reason` becomes mandatory in the AST phase.
3. Fallback-state counts must be visible in benchmark reporting.

## 11. Plan Review Pass 3

Review focus: proof of value and future sequencing.

Findings:

1. `semantic_suite` alone is insufficient to prove AST value.
2. The project needs a stress suite that targets the current heuristic failure topology.
3. LLM and data-flywheel work are still valid, but only after the static foundation is measurably improved.

Adjustments locked in:

1. Dual benchmark is mandatory:
   - baseline suite
   - stress suite
2. Field-path tracking remains the next major expansion after AST guard migration.
3. Few-Shot and autodiscovery stay downstream of static-fact quality improvements.

## 12. Final Decision Statement

The project will not continue by horizontally adding more heuristic rules first.

The next major work program is:

1. a guarded AST migration with explicit fallback and structured unknown reasons
2. followed by field-path tracking
3. followed by bounded cross-file AST inlining
4. with LLM enhancements remaining downstream and proof-centric

This plan is the current execution baseline for future implementation and expert review.
