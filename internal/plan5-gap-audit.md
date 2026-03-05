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
| P5-5 | Context budget parameters unified (`depth/lines/summaries`) | needs_refactor | `service.py` | First-hop and second-hop constants are split; no unified budget object. |
| P5-5 | Second-hop trigger rule traceability | incomplete | `service.py` | Trigger exists, but lacks explicit per-case persisted metrics. |
| P5-6 | High-confidence threshold unified for safe/risky | needs_refactor | `verification.py` | `safe` uses threshold, `risky` path still has unconditional high-confidence upgrade branch. |
| P5-6 | Conflict downgrade (safe vs risk evidence conflict) | incomplete | `verification.py` | Missing conservative downgrade gate for contradictory strong evidence. |
| P5-7 | `run-status` stage metrics completeness | needs_refactor | `cli.py`, `service.py` | Base counters exist; verify-stage and second-hop indicators missing. |
| P5-7 | `run-report` and `run-export-json` unknown_reason distribution output | incomplete | `cli.py`, `service.py` | No unknown_reason distribution in run-level outputs. |
| P5-8 | Test contracts aligned with uncertain-first + new verify gates | needs_refactor | `tests/` | Core tests exist, but several assertions still reflect old verification behavior/output shape. |

## Test Points

| Phase | Test point | Status | Current location | Notes |
|---|---|---|---|---|
| P5-1 | run start/resume/status/report/export job flow | completed | `tests/test_cli.py`, `tests/test_run_jobs.py` | Basic lifecycle and latest run selection covered. |
| P5-2 | candidate source tracking | completed | `tests/test_repository.py`, `tests/test_cli.py` | AST/fallback and counters have coverage. |
| P5-4 | uncertain-first default routing | completed | `tests/test_run_jobs.py`, `tests/test_service.py` | Default only unknown cases call backend. |
| P5-5 | second-hop trigger matrix (supports retry / no support / CLI override) | completed | `tests/test_service.py` | Main matrix exists; missing persisted observability assertions. |
| P5-6 | conflict downgrade + strict high-confidence gate | incomplete | `tests/test_verification.py` | No dedicated conflict downgrade test; old risky high-confidence path still expected. |
| P5-7 | run outputs include unknown_reason distribution + phase indicators | incomplete | `tests/test_cli.py`, `tests/test_run_jobs.py` | No assertions for unknown_reason dist and verify-stage metrics in run outputs. |
| P5-8 | legacy assertions cleanup and new contract tests | incomplete | `tests/test_verification.py`, `tests/test_cli.py`, `tests/test_service.py` | Needs migration to new run-export payload and verify conflict contract. |

## Immediate Execution Order

1. P5-5/P5-6: unify budget config, lock second-hop gating + traceability, add verify conflict downgrade and high-confidence guard.
2. P5-7: surface unknown_reason distribution and stage metrics in run status/report/export JSON.
3. P5-8: migrate tests to new contract, remove obsolete assertions, add conflict and observability contract tests.
