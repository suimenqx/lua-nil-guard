# Run Tuning Guide

This guide explains how to query and use run-store data for static-analysis tuning.

## Scope

Use this when you want to:

- inspect all collected candidates (both statically suppressed and unresolved)
- measure AST effectiveness (`ast_primary`, `ast_fallback_to_legacy`, `legacy_only`)
- correlate unknown reasons with sink rules and files
- tune `sink_rules.json`, `domain_knowledge.json`, and AST strategy based on data

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
```

`run-status` now includes:

- candidate-source counters (`ast_exact`, `lexical_fallback`)
- static-analysis mode counters (`ast_primary`, `ast_fallback_to_legacy`, `legacy_only`)
- origin-analysis mode distribution
- unknown-reason distribution for `unknown_static`

`run-export-json` includes machine-readable fields:

- `run.candidate_metrics.ast_primary_cases`
- `run.candidate_metrics.ast_fallback_to_legacy_cases`
- `run.candidate_metrics.legacy_only_cases`
- `run.analysis_mode_distribution`
- `run.origin_analysis_mode_distribution`
- `run.unknown_reason_distribution`

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

- `static_state = safe_static`: statically suppressed (not escalated)
- `static_state = unknown_static`: not statically suppressed (typically escalated)
- `analysis_mode`: guard analysis mode
- `origin_analysis_mode`: origin-tracing analysis mode

## AST Effectiveness Queries

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

1. `ast_primary` high + `safe_static` high
- AST is paying off for current rule mix.

2. `ast_fallback_to_legacy` high + `no_bounded_ast_proof` high
- AST is not proving enough; rely more on LLM, or simplify AST proof obligations.

3. `legacy_only` unexpectedly high
- inspect parser/runtime setup and candidate shapes.

4. unresolved concentrated on a few sink rules
- refine those sink rules first (`sink_rules.json`) before broad AST changes.

5. unresolved concentrated on known-safe symbol families
- add or tighten domain pruning rules (`domain_knowledge.json`).

## Important Notes

1. Domain-pruned items are not inserted into `case_tasks`.
- This is expected behavior for zero-AST fast pruning.

2. `run-report` and `run-export-json.findings` are report-oriented views.
- They are filtered by reporting policy.
- Use `case_tasks` queries for full candidate-level observability.

3. Files matched by `config/preprocessor_files.json` `skip_review_files` / `skip_review_globs` are fully omitted.
- They are not scanned, not inserted into `case_tasks`, and not parsed into macro cache.
- Use `macro-cache-status` to confirm current configured preprocessor file count.
