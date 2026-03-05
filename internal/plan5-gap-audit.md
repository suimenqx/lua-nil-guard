# Plan5 Gap Audit (2026-03-05)

## Scope

This audit marks current status for Plan5 by code and test contract:
- `completed`: matches Plan5 target contract
- `incomplete`: missing implementation or observability
- `needs_refactor`: behavior exists but contract is fragmented / unstable

## Code Points

| Phase | Point | Status | Current location | Notes |
|---|---|---|---|---|
| P5-1 | Persistent run stage machine (`INIT -> STATIC -> QUEUE -> LLM -> VERIFY -> FINALIZE`) | completed | `src/lua_nil_guard/service.py` | Runtime path and resume are in place. |
| P5-1 | Run store core tables (`runs/file_tasks/case_tasks/adjudication_records/verdict_snapshots`) | completed | `src/lua_nil_guard/service.py` | Schema and write paths exist. |
| P5-2 | `candidate_source` trace (`ast_exact/lexical_fallback`) | completed | `collector.py` + `service.py` + run status counters | Source is propagated and counted. |
| P5-3 | Structured static proof/risk + `unknown_reason` plumbing | completed | `static_analysis.py`, `pipeline.py`, `prompting.py` | Structured outputs available in packet/prompt path. |
| P5-4 | uncertain-first default (`only_unknown_for_agent=True`) | completed | `run_repository_review_job`, `run_file_review` | `safe_static` goes static verify path by default. |
| P5-5 | Context budget parameters unified (`depth/lines/summaries`) | completed | `service.py` | Unified first-hop/second-hop budget model landed (`_RelatedEvidenceBudget`). |
| P5-5 | Second-hop trigger rule traceability | completed | `service.py` | Retry is gated by `unknown_static + uncertain + backend support`; run store persists `llm_attempts/second_hop_used`. |
| P5-6 | High-confidence threshold unified for safe/risky | completed | `verification.py` | Strict score threshold now controls verified upgrade paths; weak risky evidence no longer auto-promotes to `risky_verified/high`. |
| P5-6 | Conflict downgrade (safe vs risk evidence conflict) | completed | `verification.py` | Added conservative conflict gate (`structured_conflict_downgrade`) that downgrades to `uncertain`. |
| P5-7 | `run-status` stage metrics completeness | completed | `cli.py`, `service.py` | Status/report now expose stage metrics including second-hop and verify counts. |
| P5-7 | `run-report` and `run-export-json` unknown_reason distribution output | completed | `cli.py`, `service.py` | `run-export-json` includes `run` payload with `unknown_reason_distribution` and stage metrics. |
| P5-8 | Test contracts aligned with uncertain-first + new verify gates | completed | `tests/` | Test suite migrated to new verification and run-export contracts. |

## Test Points

| Phase | Test point | Status | Current location | Notes |
|---|---|---|---|---|
| P5-1 | run start/resume/status/report/export job flow | completed | `tests/test_cli.py`, `tests/test_run_jobs.py` | Basic lifecycle and latest run selection covered. |
| P5-2 | candidate source tracking | completed | `tests/test_repository.py`, `tests/test_cli.py` | AST/fallback and counters have coverage. |
| P5-4 | uncertain-first default routing | completed | `tests/test_run_jobs.py`, `tests/test_service.py` | Default only unknown cases call backend. |
| P5-5 | second-hop trigger matrix (supports retry / no support / CLI override) | completed | `tests/test_service.py`, `tests/test_run_jobs.py` | Matrix and persisted second-hop metrics are both covered. |
| P5-6 | conflict downgrade + strict high-confidence gate | completed | `tests/test_verification.py` | Dedicated conflict downgrade and strict risk verification gate tests added. |
| P5-7 | run outputs include unknown_reason distribution + phase indicators | completed | `tests/test_cli.py`, `tests/test_run_jobs.py` | Status/report/export contracts assert stage metrics and unknown-reason distribution. |
| P5-8 | legacy assertions cleanup and new contract tests | completed | `tests/test_verification.py`, `tests/test_cli.py`, `tests/test_service.py`, `tests/test_mvp_*` | Old assertions migrated to uncertain-first + strict verification semantics. |

## Execution Result

1. Full regression passed: `447 passed`.
2. Key scenario regressions passed (macro dictionary, cross-file, module/require): `15 passed`.
3. Plan5 implementation and test migration work items are closed.
