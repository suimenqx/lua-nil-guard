# Run Tuning Guide

This guide explains how to query and use run-store data for static-analysis tuning.

## Scope

Use this when you want to:

- inspect all collected candidates (both statically suppressed and unresolved)
- measure AST-lite coverage (`ast_lite`) and domain-pruning effectiveness
- correlate unknown reasons with sink rules and files
- tune `sink_rules.json`, `domain_knowledge.json`, and AST-lite context slicing strategy based on data

## Prerequisites

1. Run a persistent review job:

```sh
lua-nil-guard run-start /path/to/target-repo
```

2. Locate the run database:

```sh
/path/to/target-repo/.lua_nil_guard/review_runs.sqlite3
```

3. Pick a run id (latest by default):

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT run_id, created_at, status
FROM runs
ORDER BY run_id DESC
LIMIT 5;
"
```

## Quick CLI Signals

Use these first for a summary:

```sh
lua-nil-guard run-status /path/to/target-repo [run_id]
lua-nil-guard run-export-json /path/to/target-repo [run_id] [output.json]
lua-nil-guard run-trace [--case-id CASE_ID] /path/to/target-repo [run_id]
lua-nil-guard case-replay /path/to/target-repo <run_id> <case_id>
```

`run-status` now includes:

- candidate-source counters (`ast_exact`, `lexical_fallback`)
- static-analysis mode counters (`ast_lite`, `domain_pruned`)
- origin-analysis mode distribution
- unknown-reason distribution for `unknown_static`
- core rates (`prune_rate`, `submission_rate`, `llm_resolution_rate`)
- end-to-end latency

`run-export-json` includes machine-readable fields:

- `run.candidate_metrics.ast_lite_cases`
- `run.candidate_metrics.pruned_cases`
- `run.candidate_metrics.prune_rate`
- `run.candidate_metrics.submission_rate`
- `run.candidate_metrics.llm_resolution_rate`
- `run.candidate_metrics.end_to_end_latency_seconds`
- `run.analysis_mode_distribution`
- `run.origin_analysis_mode_distribution`
- `run.unknown_reason_distribution`

`run-trace` and `case-replay` expose backend interaction observability:

- timeline stages (`build_command`, `execute`, `parse_response`, `fallback`)
- stage status (`started`, `completed`, `failed`)
- retries (`attempt_no`)
- trace-level behavior (`summary`, `debug`, `forensic`)
- replay summary contract (`decision_trace`) for dashboard-friendly evidence chains

## Backend Trace and Replay Queries

The backend observability data is stored in two tables:

- `backend_call_events`: stage-level backend interaction timeline
- `case_replay_capsules`: per-case replay closure

### 1) Backend event timeline by case

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT
  event_id,
  run_id,
  case_id,
  attempt_no,
  stage,
  status,
  trace_level,
  elapsed_ms,
  error_class,
  error_message
FROM backend_call_events
WHERE run_id = <RUN_ID>
ORDER BY event_id;
"
```

### 2) Backend failure hotspots

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT
  stage,
  error_class,
  COUNT(*) AS cnt
FROM backend_call_events
WHERE run_id = <RUN_ID>
  AND status = 'failed'
GROUP BY stage, error_class
ORDER BY cnt DESC, stage, error_class;
"
```

### 3) Replay capsule coverage

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT
  run_id,
  COUNT(*) AS replay_cases,
  SUM(CASE WHEN prompt_text IS NOT NULL THEN 1 ELSE 0 END) AS prompt_captured,
  SUM(CASE WHEN adjudication_payload_json IS NOT NULL THEN 1 ELSE 0 END) AS payload_captured
FROM case_replay_capsules
WHERE run_id = <RUN_ID>
GROUP BY run_id;
"
```

## Case-Level Queries (All Collected Candidates)

The `case_tasks` table stores all collected candidates in a run.

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT
  run_id,
  case_id,
  file,
  line,
  column,
  sink_rule_id,
  candidate_source,
  static_state,
  analysis_mode,
  origin_analysis_mode,
  unknown_reason,
  verdict_status
FROM case_tasks
WHERE run_id = <RUN_ID>
ORDER BY file, line, column;
"
```

Interpretation:

- `static_state = safe_static`: statically suppressed (deterministic prune path)
- `analysis_mode = domain_pruned`: deterministically pruned by domain knowledge (no LLM queue)
- `static_state = unknown_static`: default AST-lite behavior; typically escalated
- `analysis_mode`: AST-lite mode (or `domain_pruned` for deterministic prunes)
- `origin_analysis_mode`: origin-tracing mode (`ast_origin_primary`, `ast_origin_fallback`, `ast_origin_unavailable`)

## AST-lite Observability Queries

### 1) Static outcomes by analysis mode

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT analysis_mode, static_state, COUNT(*) AS cnt
FROM case_tasks
WHERE run_id = <RUN_ID>
GROUP BY analysis_mode, static_state
ORDER BY analysis_mode, static_state;
"
```

### 2) Unknown reasons by analysis mode

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT analysis_mode, unknown_reason, COUNT(*) AS cnt
FROM case_tasks
WHERE run_id = <RUN_ID>
  AND static_state = 'unknown_static'
GROUP BY analysis_mode, unknown_reason
ORDER BY cnt DESC, analysis_mode, unknown_reason;
"
```

### 3) Top unresolved sink rules

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT sink_rule_id, analysis_mode, COUNT(*) AS cnt
FROM case_tasks
WHERE run_id = <RUN_ID>
  AND static_state = 'unknown_static'
GROUP BY sink_rule_id, analysis_mode
ORDER BY cnt DESC, sink_rule_id;
"
```

### 4) File hotspots

```sh
sqlite3 /path/to/target-repo/.lua_nil_guard/review_runs.sqlite3 "
SELECT file, analysis_mode, static_state, COUNT(*) AS cnt
FROM case_tasks
WHERE run_id = <RUN_ID>
GROUP BY file, analysis_mode, static_state
ORDER BY cnt DESC, file;
"
```

## Tuning Heuristics

Use this as a baseline:

1. `ast_lite` high
- Expected in the v3 runtime path.

2. unresolved concentrated on a few sink rules
- refine those sink rules first (`sink_rules.json`) before broad context-strategy changes.

3. unresolved concentrated on known-safe symbol families
- add or tighten domain pruning rules (`domain_knowledge.json`).

## Important Notes

1. Domain-pruned items are inserted into `case_tasks` with `analysis_mode = domain_pruned`.
- Use this to compute pruning hotspots and prune-rate trends directly in SQL.

2. `run-report` and `run-export-json.findings` are report-oriented views.
- They are filtered by reporting policy.
- Use `case_tasks` queries for full candidate-level observability.

3. Files matched by `config/preprocessor_files.json` `skip_review_files` / `skip_review_globs` are fully omitted.
- They are not scanned, not inserted into `case_tasks`, and not parsed into macro cache.
- Use `macro-cache-status` to confirm current configured preprocessor file count.

4. Trace payload retention can be tuned by `config/trace_policy.json`.
- `default_trace_level`: `summary|debug|forensic`
- `max_inline_payload_bytes`: max DB inline payload size before spill-to-file
- `redact_patterns`: regex-based redaction before persistence
- `forensic` must be explicitly enabled per run (`--trace-level forensic`); do not set it as default policy
