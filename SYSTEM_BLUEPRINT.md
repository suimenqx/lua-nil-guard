# Lua Nil Risk Review Agent System Blueprint

## 1. Document Purpose

This document defines the final implementation blueprint for a high-precision, low-manual-effort system that reviews large Lua codebases for base-quality issues related to `nil` values reaching crash-prone code paths.

The primary focus is:

- Detecting whether a value that may be `nil` can reach a `nil-sensitive` sink.
- Minimizing false positives above all else.
- Using Codex / code-agent style agents as first-class reasoning components, not just report generators.
- Reducing human review cost by pushing uncertain cases through additional automated verification before escalating.

This document is the baseline specification for future system design, implementation, prompt engineering, skill design, and iteration.

## 2. Core Problem Definition

The target bug class is:

- A value that may be `nil` is passed into an operation that does not accept `nil`.
- The result is a runtime error, unexpected early exit, or silently broken control flow.

Typical examples include:

- `string.match(x, pattern)` where `x` may be `nil`
- `string.find(x, pattern)` where `x` may be `nil`
- `string.gsub(x, pattern, repl)` where `x` may be `nil`
- `table.insert(t, v)` where `t` may be `nil`
- `pairs(x)` / `ipairs(x)` where `x` may be `nil`
- `#x` where `x` may be `nil`
- `x.y` / `x[y]` where `x` may be `nil`
- String concatenation, arithmetic, or comparison where an operand may be `nil`

The real task is not “find all `nil`”.

The real task is:

- Find whether `nil` is reachable at a specific dangerous sink.
- Prove the risk path when reporting.
- Prove safety when suppressing.

## 3. Primary Design Principle

The system must optimize for `precision > recall`.

This means:

- It is acceptable to miss some edge-case risks in early versions.
- It is not acceptable to flood users with speculative warnings.
- Only risks with strong evidence should surface as final findings.
- Uncertain cases should trigger more automated analysis, not immediate human review.

This principle must govern every layer: static analysis, agent prompts, scoring, CI gating, and autofix.

## 4. Product Goals

### 4.1 Primary Goals

- Automatically scan large Lua repositories for `nil`-related crash risks.
- Keep false positives low enough that developers trust the output.
- Use agents to perform strict code reasoning with explicit evidence.
- Continuously improve by learning from confirmed safe and risky patterns.

### 4.2 Secondary Goals

- Provide structured findings that support direct remediation.
- Generate safe, minimal patch suggestions for high-confidence issues.
- Support both full-repo offline scanning and incremental PR review.

### 4.3 Non-Goals

- Full formal verification of arbitrary Lua programs
- Perfect whole-program analysis across all dynamic metaprogramming
- Generic linting for all code quality issues
- Blindly auto-fixing every flagged issue

## 5. Final Recommended Architecture

The final system should be built as a multi-layer evidence pipeline.

### 5.1 Layer A: Repository Ingestion

Responsibilities:

- Enumerate Lua files.
- Parse source into AST.
- Normalize file metadata.
- Track symbol references, scopes, and simple control-flow regions.

Recommended implementation:

- Use Tree-sitter Lua as the primary parser.
- Store source locations as stable file + line + column references.

Outputs:

- AST per file
- Symbol table per file
- Basic control-flow blocks

### 5.2 Layer B: Nil-Sensitive Sink Catalog

Responsibilities:

- Maintain the canonical list of APIs and operations that are unsafe when receiving `nil`.
- Define which argument positions are `nil-sensitive`.
- Support both built-in Lua/library sinks and project-specific sinks.

This layer must be data-driven.

Each sink rule should include:

- Qualified name
- Sensitive argument index or operand role
- Failure semantics
- Confidence level of the rule
- Suggested safe guard patterns

Examples:

- `string.match`: arg 1 must be non-nil
- `string.find`: arg 1 must be non-nil
- `table.insert`: arg 1 must be non-nil
- `member_access`: receiver must be non-nil

### 5.3 Layer C: Static Candidate Collector

Responsibilities:

- Traverse AST and identify every sink invocation or sink-equivalent operation.
- Extract the exact value expression that reaches the sink.
- Build candidate records for downstream analysis.

Important constraint:

- This layer only collects candidates.
- It must not directly emit final human-facing findings.

Outputs:

- `CandidateCase` objects, one per sink event

### 5.4 Layer D: Local Nullable Dataflow Engine

Responsibilities:

- Perform high-value, bounded static reasoning before involving agents.
- Propagate simple nullable states in local scope and intra-function control flow.

States:

- `non_nil`
- `may_nil`
- `unknown`

Evidence sources:

- Direct literal assignment
- Table constructor assignment
- Function parameter origin
- Conditional guard: `if x then`
- Assertion: `assert(x)`
- Defaulting pattern: `x = x or "..."`, `local y = x or {}`
- Explicit early return on nil

This engine should:

- Mark obviously safe cases as `safe_static`.
- Mark obviously risky cases as `risky_static` only when path evidence is strong.
- Mark all unresolved cases as `unknown_static`.

Design note:

- This layer should remain intentionally conservative.
- If certainty is missing, defer instead of over-reporting.

### 5.5 Layer E: Function Nullability Summary Cache

Responsibilities:

- Generate reusable summaries for each function.
- Capture contract-like information so agents do not re-derive the same reasoning repeatedly.

Each function summary should include:

- Function identity and file location
- Parameter non-nil requirements
- Return-value nullability per return position
- Internal guards that guarantee safety
- Known normalizers and wrappers
- Confidence and provenance

This layer is one of the highest ROI optimizations.

Benefits:

- Better cross-function reasoning
- Lower token waste
- More consistent judgments
- Lower false positives over time

### 5.6 Layer F: Repository Safety Knowledge Base

Responsibilities:

- Store learned safe and risky patterns across the codebase.
- Convert prior adjudicated results into reusable evidence.

Knowledge types:

- Safe wrapper functions
- Known normalizer helpers
- Common guard idioms
- Project-specific data contracts
- Previously confirmed false-positive patterns
- Previously confirmed true-positive patterns

This knowledge base must be versioned and auditable.

It should be updated from:

- Agent adjudications
- Human confirmations
- Runtime evidence
- Test replay results

### 5.7 Layer G: Multi-Agent Adjudication

This is the core precision layer.

Agents are not used as generic chat assistants. They are constrained reasoning workers with explicit roles.

Recommended roles:

#### G.1 Collector Agent

Responsibilities:

- Gather the analysis packet for a candidate.
- Pull local code context, function summaries, relevant callees, callers, and prior knowledge.
- Prepare a compact but sufficient evidence packet.

#### G.2 Prosecutor Agent

Responsibilities:

- Attempt to prove that `nil` can reach the sink.
- Identify the exact path and missing guard.
- Cite concrete code evidence only.

Rules:

- Must not claim risk without a reachable path narrative.
- Must identify the variable origin.

#### G.3 Defender Agent

Responsibilities:

- Attempt to prove that the sink is safe.
- Identify guard coverage, contracts, wrappers, normalizers, or path exclusions.

Rules:

- Must cite explicit safety evidence.
- Must reject speculative “probably safe” logic.

#### G.4 Judge Agent

Responsibilities:

- Compare both sides.
- Assign the final verdict.
- Request more evidence when proof is incomplete.

Final verdict states:

- `safe`
- `risky`
- `uncertain`

Important rule:

- `uncertain` is not a final human-facing issue.
- It triggers more automated analysis.

### 5.8 Layer H: Automatic Verification Loop

Responsibilities:

- Reduce residual uncertainty without human involvement.
- Validate or downgrade agent judgments.

Verification strategies:

- Expand context window and re-run adjudication
- Pull more callers or callees
- Use runtime evidence if available
- Attempt minimal reproduction under test harness
- Inject `nil` at target boundary in a controlled validation run

Expected outcomes:

- Upgrade to `risky_verified`
- Downgrade to `safe_verified`
- Remain `uncertain_exhausted`

Only after this loop is exhausted should a case be considered for human escalation.

### 5.9 Layer I: Reporting, CI, and Autofix

Responsibilities:

- Emit structured findings.
- Gate new high-confidence regressions.
- Propose minimal fixes where safe.

Rules:

- Only `risky` or `risky_verified` with sufficient confidence should enter reports.
- `uncertain` should stay internal unless explicitly requested.
- Baseline mode should suppress pre-existing debt when rolling out on legacy repositories.

## 6. End-to-End Workflow

The full lifecycle for a single candidate case is:

1. Parse Lua source into AST.
2. Identify a `nil-sensitive` sink.
3. Create a candidate record.
4. Run local nullable analysis.
5. If statically safe, suppress.
6. If unresolved, attach function summaries and knowledge-base facts.
7. Build an agent evidence packet.
8. Run Prosecutor and Defender.
9. Run Judge.
10. If `uncertain`, automatically expand evidence and re-run.
11. If still uncertain, attempt runtime or test-based verification if supported.
12. Only surface cases with sufficient proof.
13. Optionally generate patch suggestions.
14. Feed final outcome back into summary cache and knowledge base.

## 7. Decision Policy and Confidence Model

The system must use explicit confidence gates.

### 7.1 Confidence Inputs

- Strength of sink rule
- Strength of variable-origin evidence
- Control-flow path clarity
- Presence or absence of guards
- Function summary confidence
- Knowledge-base corroboration
- Runtime/test validation result
- Agreement between Prosecutor and Judge
- Successful rebuttal by Defender

### 7.2 Final Confidence Levels

- `high`: strong path evidence, no valid rebuttal, or runtime verification confirms risk
- `medium`: probable risk, but some context remains incomplete
- `low`: weak or speculative evidence

### 7.3 Reporting Threshold

Recommended default:

- Only report `high` confidence issues by default.
- Optionally include `medium` in offline audit mode.
- Never include `low` in default human-facing output.

### 7.4 Hard Rules

- No path evidence means no `high`.
- No explicit safety evidence means not automatically `safe`.
- No conclusion should be upgraded from `uncertain` to `risky` without new evidence.

## 8. Data Model Specification

The system should be built around stable, structured records.

### 8.1 `SinkRule`

```json
{
  "id": "string.match.arg1",
  "kind": "function_arg",
  "qualified_name": "string.match",
  "arg_index": 1,
  "nil_sensitive": true,
  "failure_mode": "runtime_error",
  "default_severity": "high",
  "safe_patterns": ["x or ''", "assert(x)", "if x then ... end"]
}
```

### 8.2 `CandidateCase`

```json
{
  "case_id": "case_000123",
  "file": "foo/bar.lua",
  "line": 128,
  "column": 17,
  "sink_rule_id": "string.match.arg1",
  "expression": "username",
  "symbol": "username",
  "function_scope": "parse_user",
  "static_state": "unknown_static"
}
```

### 8.3 `FunctionSummary`

```json
{
  "function_id": "foo/bar.lua::parse_user:42",
  "params": [
    {"name": "req", "nullability": "may_nil"},
    {"name": "name", "nullability": "non_nil_if_guarded"}
  ],
  "returns": [
    {"index": 1, "nullability": "may_nil"}
  ],
  "guards": [
    "if name then",
    "assert(req)"
  ],
  "known_normalizers": [
    "normalize_name"
  ],
  "confidence": "medium",
  "source": "static+agent"
}
```

### 8.4 `EvidencePacket`

```json
{
  "case_id": "case_000123",
  "target": {
    "file": "foo/bar.lua",
    "line": 128,
    "sink": "string.match",
    "arg_index": 1,
    "expression": "username"
  },
  "local_context": "...",
  "related_functions": ["..."],
  "function_summaries": ["..."],
  "knowledge_facts": ["normalize_name always returns string"],
  "static_reasoning": {
    "state": "unknown_static",
    "observed_guards": [],
    "origin_candidates": ["req.params.username"]
  }
}
```

### 8.5 `Verdict`

```json
{
  "case_id": "case_000123",
  "status": "risky",
  "confidence": "high",
  "risk_path": [
    "username <- req.params.username",
    "no guard before string.match(username, ...)"
  ],
  "safety_evidence": [],
  "counterarguments_considered": [
    "No upstream normalizer found"
  ],
  "suggested_fix": "local safe_name = username or ''",
  "needs_human": false
}
```

## 9. Agent Skill Design Specification

The system should include a dedicated skill for strict Lua nil-risk adjudication.

This skill is not a generic coding helper. It is a constrained review protocol.

### 9.1 Skill Objectives

- Judge only whether `nil` can reach a `nil-sensitive` sink.
- Use explicit code evidence.
- Minimize false positives.
- Avoid speculation.

### 9.2 Mandatory Behavioral Rules

- Only reason from provided code and declared facts.
- Always search for safety evidence before confirming risk.
- Never mark a case `risky` without a concrete path explanation.
- Never mark a case `safe` without explicit supporting evidence.
- If evidence is insufficient, return `uncertain`.
- Distinguish code fact from inference.
- Cite file and line references when available.

### 9.3 Required Output Schema

Every agent response should be machine-readable and include:

- `status`
- `confidence`
- `risk_path`
- `safety_evidence`
- `missing_evidence`
- `recommended_next_action`
- `suggested_fix` if and only if confidence is sufficient

### 9.4 Recommended Prompt Skeleton

Each adjudication prompt should include:

- The target sink and rule
- The code slice
- Known summaries
- Known safe/risky patterns
- A hard instruction to avoid speculation
- The exact output schema

The prompt must explicitly state:

- “Unknown is not risk.”
- “Absence of proof is not proof of bug.”

## 10. Context Assembly Strategy

Low-quality context is a major source of false positives. Context assembly must be explicit and staged.

### 10.1 Minimum Context

- Candidate line
- Enclosing function
- Preceding assignments
- Nearby guards
- Relevant return statements

### 10.2 Expanded Context

Triggered only when needed:

- Callee bodies
- Return-source functions
- Immediate callers
- Normalizer wrappers
- Summary and knowledge facts

### 10.3 Stop Conditions

Stop expanding when:

- The case reaches `safe` or `risky` with sufficient confidence
- Additional context stops changing the verdict
- Configured depth or token budget is reached

## 11. Automated Verification Strategy

This is the key system optimization beyond prompt quality.

### 11.1 Static Re-check

If a case remains uncertain:

- Expand the dataflow slice
- Recompute summary dependencies
- Re-run adjudication

### 11.2 Runtime Signal Injection

Where infrastructure allows:

- Add lightweight probes around high-value sinks
- Record whether target arguments are ever nil in test or staging runs
- Track observed invariants for heavily used APIs

Use runtime data carefully:

- Runtime absence of nil is supporting evidence, not absolute proof
- Runtime presence of nil is strong evidence of real risk

### 11.3 Minimal Reproduction Validation

For high-value cases:

- Attempt a controlled reproduction by injecting `nil` into the relevant boundary under test
- Observe whether the sink crashes

This step is especially useful before filing high-priority issues or applying autofix at scale.

## 12. Reporting and Human Escalation Policy

Human attention is expensive. The reporting policy must reflect that.

### 12.1 Default Human-Facing Output

Only include:

- `risky` or `risky_verified`
- `high` confidence by default
- Clear proof path
- Minimal fix recommendation

### 12.2 Internal-Only States

Do not show by default:

- `safe`
- `safe_verified`
- `uncertain`
- `low` confidence

### 12.3 Human Escalation Criteria

Escalate only if all of the following apply:

- The case remains unresolved after automated evidence expansion
- The sink severity is high
- The code path is business-critical
- Further automation would be disproportionately expensive

## 13. Autofix Policy

Autofix should be conservative and minimal.

### 13.1 Eligible Cases

- High-confidence risks only
- Clear, local, low-side-effect fixes only

### 13.2 Preferred Fix Patterns

- `local safe_x = x or ""`
- `if not x then return ... end`
- `assert(x, "expected non-nil x")`
- Default empty table where behaviorally safe

### 13.3 Forbidden Fix Behavior

- Do not silently change behavior when semantic meaning is unclear.
- Do not apply fallback values that may mask business bugs without review.
- Do not auto-commit broad refactors.

## 14. Rollout Strategy

### 14.1 Phase 1: Offline Audit Mode

Build first in non-blocking mode:

- Full repository scan
- Structured report
- No CI failure
- Manual sampling for precision measurement

Goal:

- Validate that reported issues are trustworthy

### 14.2 Phase 2: Baseline Mode

Introduce baseline suppression:

- Record known historical findings
- Only highlight newly introduced high-confidence risks

Goal:

- Prevent new debt without overwhelming teams

### 14.3 Phase 3: Incremental PR Review

Scope analysis to changed files and impacted call graph regions.

Goal:

- Fast feedback during code review

### 14.4 Phase 4: Controlled Autofix

Allow auto-generated patch proposals for a narrow class of high-confidence findings.

Goal:

- Reduce remediation labor

## 15. Recommended Implementation Roadmap

### 15.1 MVP

Build the first usable system with:

- Tree-sitter Lua parsing
- Initial sink catalog
- Local nullable propagation
- Candidate generation
- Single evidence packet generator
- Prosecutor + Defender + Judge flow
- High-confidence report output

MVP success criteria:

- Produces few but credible findings
- Developers perceive low noise

### 15.2 V2

Add:

- Function summary cache
- Repository knowledge base
- Baseline mode
- Better context expansion

V2 success criteria:

- Noticeable drop in repeated false positives
- Better cross-function reasoning

### 15.3 V3

Add:

- Runtime evidence integration
- Minimal reproduction validation
- Limited autofix
- PR integration

V3 success criteria:

- Human triage load is materially reduced
- High-confidence alerts are actionable and trusted

## 16. Suggested Project Structure

One practical structure for implementation:

```text
/
  SYSTEM_BLUEPRINT.md
  docs/
    sink-rules.md
    prompting.md
  config/
    sink_rules.json
    confidence_policy.json
  skills/
    lua-nil-adjudicator/
      SKILL.md
  src/
    parser/
    collector/
    dataflow/
    summaries/
    knowledge/
    agents/
    verifier/
    reporting/
  tests/
    fixtures/
    integration/
```

## 17. Key Metrics

The system must be measured by precision-oriented metrics.

Primary metrics:

- Confirmed precision of `high` findings
- Human-review cases per 1,000 Lua files
- Percentage of `uncertain` cases resolved automatically
- Repeat false-positive rate

Secondary metrics:

- Candidate-to-final finding reduction ratio
- Average tokens per adjudicated case
- Average analysis latency per changed file
- Autofix acceptance rate

## 18. Risks and Mitigations

### 18.1 Risk: Excessive False Positives

Mitigation:

- High reporting threshold
- Defender and Judge roles
- Knowledge base
- Runtime verification

### 18.2 Risk: Token Cost Explosion

Mitigation:

- Function summary cache
- Context staging
- Only send unresolved cases to agents
- Incremental analysis

### 18.3 Risk: Dynamic Lua Features Break Analysis

Mitigation:

- Keep static analysis conservative
- Prefer `uncertain` over overconfident claims
- Use runtime evidence for dynamic hotspots

### 18.4 Risk: Unsafe Autofix

Mitigation:

- Restrict autofix to narrow patterns
- Require high confidence
- Keep patch scope minimal

## 19. Final System Policy

The final system should operate under these fixed policies:

- Precision is the top priority.
- Agents must reason with evidence, not intuition.
- Uncertain cases should be automated further before involving humans.
- Learned safe patterns are first-class assets and must be persisted.
- Reports should be sparse, structured, and trustworthy.
- The system should become more accurate over time through memory, validation, and feedback.

## 20. Immediate Next Development Steps

Implement in this order:

1. Define the initial `sink_rules.json`.
2. Build the Tree-sitter parsing and candidate collector.
3. Implement local nullable propagation and static suppression.
4. Define the agent evidence packet schema.
5. Implement the `Collector`, `Prosecutor`, `Defender`, and `Judge` workflow.
6. Add structured report generation for high-confidence findings.
7. Add function summary caching.
8. Add knowledge-base writeback for safe and risky patterns.
9. Add baseline mode.
10. Add runtime/test verification and then selective autofix.

## 21. Final Recommendation

The best final design is not a simple linter and not a single-pass LLM reviewer.

The best design is:

- A static-analysis front end for broad collection
- A conservative nullable engine for first-pass suppression
- A summary and memory layer for reusable codebase knowledge
- A multi-agent, evidence-based adjudication core
- An automatic verification loop for uncertainty reduction
- A sparse, high-trust reporting and remediation layer

This design best matches the project goal:

- Spend more machine reasoning and token budget
- Spend less human attention
- Surface fewer, stronger, more actionable findings

