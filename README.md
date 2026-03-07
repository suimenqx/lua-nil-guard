# LuaNilGuard

`lua-nil-guard` is a developer-facing CLI for reviewing Lua code for likely nil-related runtime faults. The supported operating model is source-tree usage: keep this repository intact, run from the checkout, and point the tool at Lua repositories you want to inspect.

Chinese documentation: [README.zh-CN.md](./README.zh-CN.md)

## Requirements

- Python 3.12+
- A source checkout of this repository
- `pip install -e .` from this checkout

## Quick Start

1. Create and activate a virtual environment.
2. Install the project in editable mode:

```sh
pip install -e .
```

You only need to run this once per Python environment. Re-run it only after switching environments or after packaging changes such as dependency or CLI-entrypoint updates.

3. Verify Tree-sitter is available before running analysis:

```sh
lua-nil-guard doctor
```

4. Initialize the target repository config:

```sh
lua-nil-guard init-config /path/to/target-repo
```

5. By default, LuaNilGuard skips `id.lua` and `*_id.lua` from both review scanning and macro-cache parsing, so giant generated dictionaries do not impact response time. If you want to ingest compile-time facts from selected files, configure `config/preprocessor_files.json`, then audit/cache what the tool can ingest:

```sh
lua-nil-guard macro-audit /path/to/target-repo
lua-nil-guard macro-build-cache /path/to/target-repo
lua-nil-guard macro-cache-status /path/to/target-repo
```

Configured preprocessor files are treated as preprocessor inputs only: they provide compile-time non-nil facts, but they are not scanned as ordinary business Lua review targets.
LuaNilGuard compiles and reuses a local macro cache for those configured files so repeated runs do not need to reparse unchanged giant dictionary files.

6. If the repository may contain legacy-encoded Lua files, audit and normalize them first:

```sh
lua-nil-guard encoding-audit /path/to/target-repo
lua-nil-guard normalize-encoding --write /path/to/target-repo
```

7. Run a static scan:

```sh
lua-nil-guard scan /path/to/target-repo
```

8. Run a full report:

```sh
lua-nil-guard report /path/to/target-repo
```

## Persistent Run Workflow

For long-running repository review jobs with resume/status/report/export support, use:

```sh
lua-nil-guard run-start [--trace-level summary|debug|forensic] /path/to/target-repo
lua-nil-guard run-status /path/to/target-repo [run_id]
lua-nil-guard run-report /path/to/target-repo [run_id]
lua-nil-guard run-export-json /path/to/target-repo [run_id] [output]
lua-nil-guard run-resume [--trace-level summary|debug|forensic] /path/to/target-repo <run_id>
lua-nil-guard run-trace [--case-id CASE_ID] /path/to/target-repo [run_id]
lua-nil-guard run-trace-json [--case-id CASE_ID] /path/to/target-repo [run_id] [output]
lua-nil-guard case-replay /path/to/target-repo <run_id> <case_id>
lua-nil-guard case-replay-json /path/to/target-repo <run_id> <case_id> [output]
```

`run-status` and `run-report` now include stage metrics and unknown-reason distribution, including:

- candidate/source counters (`ast_exact`, `lexical_fallback`)
- static analysis mode counters (`ast_lite`, `domain_pruned`)
- static-layer counters (`safe_static`, `unknown_static`)
- lifecycle counters (`pruned_cases`, `llm_enqueued`, `llm_processed`, `llm_resolved`)
- rate metrics (`prune_rate`, `submission_rate`, `llm_resolution_rate`)
- end-to-end latency (`end_to_end_latency_seconds`)
- LLM-layer counters (`llm_enqueued`, `llm_processed`, `llm_second_hop`)
- verify-layer counters (`safe_verified`, `risky_verified`)
- `unknown_reason` distribution for `unknown_static` cases

For full tuning and candidate-level observability queries, see [`docs/run-tuning.md`](docs/run-tuning.md).

### Backend Interaction Trace and Case Replay

Use this when you want auditable backend interaction timeline and one-case replay:

```sh
lua-nil-guard run-start --trace-level debug /path/to/target-repo
lua-nil-guard run-trace /path/to/target-repo [run_id]
lua-nil-guard case-replay /path/to/target-repo <run_id> <case_id>
lua-nil-guard clear-trace-artifacts /path/to/target-repo [run_id]
```

Trace levels:

- `summary` (default): metadata/timeline only
- `debug`: includes prompt and structured response payloads
- `forensic`: includes stderr/raw envelope fields (explicit opt-in recommended)

The default trace behavior is controlled by `config/trace_policy.json`:

```json
{
  "default_trace_level": "summary",
  "max_inline_payload_bytes": 65536,
  "redact_patterns": [
    "(?i)(authorization\\s*[:=]\\s*)([^\\s,;]+)",
    "(?i)(api[_-]?key\\s*[:=]\\s*)([^\\s,;]+)"
  ]
}
```

When payload size exceeds `max_inline_payload_bytes`, trace payloads are spilled under `.lua_nil_guard/traces/<run_id>/...`, and DB rows keep a descriptor (path/hash/bytes).

`run-export-json` now exports a structured object:

```json
{
  "run": {
    "run_id": 12,
    "stage_metrics": {
      "static": {"total_cases": 120, "safe_static_cases": 80, "unknown_static_cases": 40},
      "queue": {"llm_enqueued_cases": 40},
      "llm": {"llm_processed_cases": 40, "llm_second_hop_cases": 7},
      "verify": {"safe_verified_cases": 86, "risky_verified_cases": 21},
      "finalize": {"completed_cases": 120, "failed_cases": 0}
    },
    "candidate_metrics": {
      "ast_lite_cases": 120
    },
    "unknown_reason_distribution": [
      {"reason": "no_bounded_ast_proof", "count": 31}
    ]
  },
  "findings": [
    {
      "case_id": "...",
      "status": "risky_verified",
      "confidence": "high"
    }
  ]
}
```

If you want a faster first pass that only focuses on string-library and string-concat nil hazards, use:

```sh
lua-nil-guard scan --focus string /path/to/target-repo
lua-nil-guard report --focus string /path/to/target-repo
```

## Single-File Review

If you only want to inspect one Lua file, use the file entrypoints. The file still needs to live inside a repository that has been initialized with `init-config`.

```sh
lua-nil-guard scan-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file-json /path/to/target-repo/src/demo.lua
```

For a string-only single-file pass:

```sh
lua-nil-guard scan-file --focus string /path/to/target-repo/src/demo.lua
lua-nil-guard report-file --focus string /path/to/target-repo/src/demo.lua
```

Single-file review keeps repository context, so cross-file function summaries and related function source snippets can still be used during adjudication.

## Default High-Risk Coverage

Out of the box, LuaNilGuard prioritizes Lua nil hazards that commonly lead to immediate runtime faults:

- string-library first-argument sinks such as `string.find`, `string.match`, `string.gsub`, `string.sub`, `string.len`, `string.byte`, `string.lower`, and `string.upper`
- string concatenation with `..` (both operands are checked independently)
- table iteration via `pairs(...)` and `ipairs(...)`
- length operator usage with `#value`
- numeric ordering comparisons: `<`, `<=`, `>`, `>=` (`==` and `~=` are intentionally excluded)
- numeric arithmetic: `+`, `-`, `*`, `/`, `%`, `^` (both operands are checked independently)

These patterns are part of the default `sink_rules.json` template and are intended to be the first customer-visible value surface during trial use. `member_access.receiver` is intentionally not enabled by default; add it manually if your repository wants broad receiver nil checks.

## Recommended First Run

For a first trial, do not start with a full repository scan. Start with one representative Lua file, then tighten configuration only if the result is too uncertain.

1. Initialize the target repository once:

```sh
lua-nil-guard init-config /path/to/target-repo
```

2. Verify the parser environment first:

```sh
lua-nil-guard doctor
```

3. If the repository was edited by older Windows tools, run an encoding check first:

```sh
lua-nil-guard encoding-audit /path/to/target-repo
lua-nil-guard normalize-encoding --write /path/to/target-repo
```

4. Pick one real file with a known nil-sensitive call and run:

```sh
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
```

5. If the result is already `risky` or `safe`, keep iterating on small files before moving to a wider scan.

6. If the result is mostly `uncertain`, check whether the file depends on helper functions that are not defined in the current repository checkout. In that case, add a narrow contract to `config/function_contracts.json` instead of widening the scan immediately.

Typical examples:

- A guard helper that proves its arguments are non-nil:

```json
[
  {
    "qualified_name": "assert_present",
    "ensures_non_nil_args": [1]
  }
]
```

- A normalizer that is only safe when called with a known fallback:

```json
[
  {
    "qualified_name": "normalize_name",
    "returns_non_nil": true,
    "applies_with_arg_count": 2,
    "required_literal_args": {
      "2": "''"
    },
    "applies_to_call_roles": ["assignment_origin", "sink_expression"]
  }
]
```

7. Re-run the same file after updating contracts. Only after a few representative files behave well should you move on to:

```sh
lua-nil-guard report /path/to/target-repo
```

8. If you want to see what the tool still cannot prove, inspect the proposal backlog:

```sh
lua-nil-guard proposal-analytics /path/to/target-repo
```

This report is most useful after you have already tried a few single-file runs. It helps separate:

- truly unresolved patterns that may need new bounded recognizers
- helper functions that may need an explicit contract

If your repository uses giant preprocessor-style macro dictionary files (for example `NAME = ""` or `Defaults.Name = 0` files that are consumed at build time), configure the files you want to parse in `config/preprocessor_files.json`, then run:

```sh
lua-nil-guard macro-audit /path/to/target-repo
lua-nil-guard macro-build-cache /path/to/target-repo
lua-nil-guard macro-cache-status /path/to/target-repo
```

`macro-audit` shows:

- which configured macro files were loaded
- which macro lines were converted into compile-time facts
- which lines were left unresolved because they were outside the bounded supported syntax

`macro-build-cache` prebuilds the compiled macro cache, and `macro-cache-status` tells you whether the cache is fresh or needs a rebuild. Normal review commands also reuse the cache automatically when it is fresh. The cache is rebuilt automatically when a matched preprocessor file changes, when the effective preprocessor-file configuration changes, or when the cache schema changes.

## Backends

Repository CLI commands now resolve the default backend from `config/backend.json` when `--backend` is omitted:

```json
{
  "default_backend": "codex"
}
```

If neither `--backend` nor `config/backend.json` is provided, the command exits with an explicit setup hint.

You can also choose another supported CLI integration with `--backend`:

- `gemini`
- `claude`
- `codex`
- `heuristic` (debug/test only)

The service-layer APIs (`run_repository_review`, `run_file_review`, `run_repository_review_job`, `benchmark_repository_review`, and `draft_review_improvements`) still default to `codex` when `backend` is not provided programmatically.

Examples:

```sh
lua-nil-guard report --backend gemini /path/to/target-repo
lua-nil-guard report-file --backend gemini /path/to/target-repo/src/demo.lua
```

Those backends require the corresponding local CLI tool, credentials, and network access to already be working on the machine. For custom providers, generate a starter manifest with:

```sh
lua-nil-guard generate-backend-manifest my-provider stdout_envelope_cli
```

### Codex Review Playbook

Recommended command path for Codex-based Lua nil-risk review:

1. Preflight checks:

```sh
codex exec --version
lua-nil-guard doctor
```

2. Validate on one file first:

```sh
lua-nil-guard report-file \
  --backend codex \
  --model gpt-5.1-codex-mini \
  --backend-config 'model_reasoning_effort="high"' \
  /path/to/target-repo/src/demo.lua
```

3. Expand to repository review:

```sh
lua-nil-guard report \
  --backend codex \
  --model gpt-5.1-codex-mini \
  --backend-config 'model_reasoning_effort="high"' \
  /path/to/target-repo
```

4. Run benchmark and inspect quality/latency:

```sh
lua-nil-guard benchmark \
  --backend codex \
  --model gpt-5.1-codex-mini \
  --backend-config 'model_reasoning_effort="high"' \
  /path/to/labeled-repo
```

Benchmark note: labeled files must follow `provable_risky_*`, `provable_safe_*`, or `provable_uncertain_*`.

If benchmark accuracy is unexpectedly low and `backend_fallbacks` is high (or equals total cases), inspect backend failures first:

```sh
lua-nil-guard benchmark-json \
  --backend codex \
  --model gpt-5.1-codex-mini \
  --backend-config 'model_reasoning_effort="high"' \
  /path/to/labeled-repo \
  build/benchmark_codex.json
```

Then check `cases[*].backend_failure_reason` in the JSON. A common issue is an incompatible global Codex setting in `~/.codex/config.toml`, such as `model_reasoning_effort = "xhigh"` for models that only support `low|medium|high`. Override per run with `--backend-config 'model_reasoning_effort="high"'` or update your global Codex config.

### Gemini Review Playbook

Recommended command path for Gemini-based Lua nil-risk review:

1. Preflight checks:

```sh
gemini --version
lua-nil-guard doctor
```

2. Validate on one file first:

```sh
lua-nil-guard report-file \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/target-repo/src/demo.lua
```

3. Expand to repository review:

```sh
lua-nil-guard report \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/target-repo
```

4. Benchmark and export JSON for diagnosis:

```sh
lua-nil-guard benchmark-json \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/labeled-repo \
  build/benchmark_gemini.json
```

Benchmark note: labeled files must follow `provable_risky_*`, `provable_safe_*`, or `provable_uncertain_*`.

Practical tuning guidance:

- If `backend_fallbacks` or `backend_timeouts` is high, increase `--backend-timeout` first (recommended range: `60-120` seconds).
- Keep `--backend-attempts 1` for stable links and lower latency; use `2` or `3` when network/API jitter exists.
- If you see `ERR_STREAM_PREMATURE_CLOSE` in `cases[*].backend_failure_reason`, treat it as transient backend transport failure and retry with higher `--backend-attempts`.
- Start with the default Gemini model first; if you switch to a faster model (for example `--model gemini-2.5-flash`), verify timeout behavior again because latency and response stability may differ.

Observed in local practice on `examples/mvp_cases/agent_semantic_suite` (March 7, 2026):

- `--backend-timeout 25 --backend-attempts 1`: all cases fell back, benchmark degraded heavily.
- `--backend-timeout 90 --backend-attempts 1`: `17/18` exact matches (`94.4%`), with one fallback caused by a transient `ERR_STREAM_PREMATURE_CLOSE`.

For a compact step-by-step guide (including custom backend manifest setup and model pinning), see [`docs/gemini-playbook.md`](docs/gemini-playbook.md).

## Repository Layout

Target repositories are expected to contain:

- `config/sink_rules.json`
- `config/confidence_policy.json`
- `config/function_contracts.json`
- `config/preprocessor_files.json`
- `config/domain_knowledge.json`
- `config/backend.json`
- `config/trace_policy.json`

`init-config` writes the default versions of all seven files into the target repository. `function_contracts.json` lets you declare high-confidence wrapper functions such as `normalize_name` that always return a non-nil value, helper guards such as `assert_profile(profile)` via `ensures_non_nil_args`, and normalizers that return a defaulted non-nil value from specific arguments via `returns_non_nil_from_args`. For multi-return helpers you can further split those argument requirements by consumed return slot with `returns_non_nil_from_args_by_return_slot`, so slot `1` and slot `2` do not have to share the same safety preconditions. You can also require that certain input arguments have already been guarded before trusting a specific return slot by using `requires_guarded_args_by_return_slot`, which lets a guard helper contract and a later normalizer contract work together in one proof chain. You can also restrict a contract to specific caller modules with `applies_in_modules`, to specific caller function scopes with `applies_in_function_scopes`, to scope kinds with `applies_to_scope_kinds` (`top_level`, `function_body`), to top-level phases with `applies_to_top_level_phases` (`init`, `post_definitions`), to specific sink rules or sink names with `applies_to_sinks`, to specific call positions with `applies_to_call_roles` (`assignment_origin`, `sink_expression`, `guard_call`), to specific return-value usage modes with `applies_to_usage_modes` (`single_assignment`, `multi_assignment`, `direct_sink`), to specific selected return slots with `applies_to_return_slots` (for example only return slot `1` in a multi-return helper), to a specific call arity with `applies_with_arg_count`, to exact literal arguments with `required_literal_args`, to argument-source shapes with `required_arg_shapes` (`identifier`, `member_access`, `indexed_access`, `literal`, `call`, `expression`), to argument root symbols with `required_arg_roots` (for example `req`, `ngx`, or `fallbacks`), to dotted access-path prefixes with `required_arg_prefixes` (for example `req.params` or `ngx.var`), and to exact normalized access chains with `required_arg_access_paths` (for example `req.params.user` or `req.params[1]`) when a helper is only trustworthy for one exact lookup path. Quoted literal table keys such as `req.params["user"]` normalize to the same `req.params.user` path, while dynamic indexes such as `req.params[token]` do not count as an exact match. This helps suppress false positives without relying on prompt-only inference.

`sink_rules.json` intentionally does not include `member_access.receiver` by default. Add it explicitly when your team wants broad receiver checks:

```json
{
  "id": "member_access.receiver",
  "kind": "receiver",
  "qualified_name": "member_access",
  "arg_index": 0,
  "nil_sensitive": true,
  "failure_mode": "runtime_error",
  "default_severity": "high",
  "safe_patterns": ["assert(x)", "if x then ... end"]
}
```

`domain_knowledge.json` supports deterministic zero-AST fast pruning for known-safe symbol families. The default template includes rules for `_name_*` tables, `_cmd_*` tables, and all-uppercase underscore macros:

```json
{
  "rules": [
    {
      "id": "system_name_table_prefix",
      "action": "skip_candidate",
      "symbol_regex": "^_name_[A-Z0-9_]+(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$",
      "applies_to_sinks": ["member_access.receiver", "pairs.arg1", "ipairs.arg1", "length.operand"]
    },
    {
      "id": "uppercase_macro_non_nil",
      "action": "skip_candidate",
      "symbol_regex": "^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$",
      "applies_to_sinks": []
    }
  ]
}
```

Quick-start configuration flow for new repositories:

1. Keep defaults from `lua-nil-guard init-config`.
2. Only add `member_access.receiver` if your team wants receiver-wide checks.
3. Add narrow domain rules for your naming conventions first, then expand.

Example: `_id_.*` symbols are treated as stable numeric non-nil values:

```json
{
  "id": "id_numeric_non_nil",
  "action": "skip_candidate",
  "symbol_regex": "^_id_[A-Z0-9_]+$",
  "applies_to_sinks": [
    "compare.lt.left",
    "compare.lt.right",
    "compare.lte.left",
    "compare.lte.right",
    "compare.gt.left",
    "compare.gt.right",
    "compare.gte.left",
    "compare.gte.right",
    "arithmetic.add.left",
    "arithmetic.add.right",
    "arithmetic.sub.left",
    "arithmetic.sub.right",
    "arithmetic.mul.left",
    "arithmetic.mul.right",
    "arithmetic.div.left",
    "arithmetic.div.right"
  ],
  "assumed_non_nil": true,
  "assumed_kind": "number"
}
```

Example: global default table variables are always present:

```json
{
  "id": "global_default_tables",
  "action": "skip_candidate",
  "symbol_regex": "^_g_[A-Z0-9_]+(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$",
  "applies_to_sinks": [
    "member_access.receiver",
    "pairs.arg1",
    "ipairs.arg1",
    "length.operand"
  ],
  "assumed_non_nil": true,
  "assumed_kind": "table"
}
```

Practical guardrails:

- Start with exact prefixes (`^_name_`, `^_cmd_`, `^_id_`) instead of broad patterns.
- Add sink scope (`applies_to_sinks`) before using catch-all scopes.
- Validate with one file first (`report-file`), then expand to repository scan.

`preprocessor_files.json` controls file classification for giant generated Lua:

- `preprocessor_files` / `preprocessor_globs`: parse as macro dictionaries (compile-time facts only, no normal candidate scan)
- `skip_review_files` / `skip_review_globs`: skip completely (no scan, no macro parsing, no cache work)

Default template:

```json
{
  "preprocessor_files": [],
  "preprocessor_globs": [],
  "skip_review_files": [],
  "skip_review_globs": ["id.lua", "*_id.lua"]
}
```

If you do want to parse selected `id.lua` style files as macro dictionaries, move those rules to `preprocessor_*` and remove them from `skip_review_*`.

LuaNilGuard can ingest bounded facts such as:

- `NAME = ""`
- `COUNT = 0`
- `AAA = 0x100` (normalized to decimal for numeric checks)
- `Defaults.Name = ""`
- `cmd_id.dis = {0x14, "display"}` (recognized as a non-nil table literal)
- `ALIAS = NAME`

For dotted assignments (for example `a.b = 1`), LuaNilGuard also infers parent table presence (`a`) as a non-nil table fact. These facts are then used to suppress false positives in high-value nil hazard checks while keeping reports anchored to the original source file the developer edits.

## Adjudication Mode

LuaNilGuard v3 always uses single-pass structured adjudication.
`--adjudication-mode` has been removed from the CLI.
`config/adjudication_policy.json` also supports only `single_pass`.

## Calibration

After running reviews, use `calibration-status` to inspect the offline calibration data:

```sh
lua-nil-guard calibration-status /path/to/target-repo
```

Calibration buckets track historical precision by sink type and unknown reason. When enough samples accumulate, the system can automatically downgrade overconfident LLM verdicts.

## Incremental Analysis

For PR-level workflows, use `run-incremental` to only re-analyze files affected by changes:

```sh
lua-nil-guard run-incremental --changed-files src/a.lua,src/b.lua /path/to/target-repo
```

This requires a previous full run (`run-start`) to have populated file fingerprints and dependency data. If incremental analysis is not available, it will suggest falling back to a full run.

## Nil Guard Annotations

Developers can annotate functions with `--- @nil_guard` comments to declare nil contracts:

```lua
--- @nil_guard: returns_non_nil
function normalize_name(raw)
    return raw or ""
end
```

LuaNilGuard uses annotations as high-priority evidence for cross-function reasoning. See `docs/annotations.md` for the full syntax reference.

Related commands:

```sh
lua-nil-guard annotation-coverage /path/to/target-repo
lua-nil-guard annotation-suggest /path/to/target-repo/src/demo.lua
```

## Notes

- This release is intended for developer trial use. Start with a few real files or one small module before using it across a large repository.
- Tree-sitter is required for formal analysis commands (`scan`, `report`, `report-file`, `benchmark`, and proposal commands). If `doctor` reports that Tree-sitter is unavailable, fix the parser environment first instead of relying on a degraded mode.
- LuaNilGuard only uses the vendored Lua grammar compiled locally through `cc`, `gcc`, or `clang`. It does not fall back to an externally installed `tree_sitter_lua` package, so parser behavior stays reproducible across machines.
- Lua source files are expected to be UTF-8. Use `encoding-audit` to find non-UTF-8 `.lua` files and `normalize-encoding --write` to convert supported legacy files (`utf-8-sig`, `gb18030`) before review.
- Single-file review works best when important helper functions are either present in the same repository or represented in `config/function_contracts.json`.
- Missing helper definitions do not block review, but they reduce cross-file proof strength and can increase `uncertain` results.
- Bare global `require("module.name")` declarations are treated as non-nil module symbols for nil-risk review, so member-access checks do not repeatedly report those module receivers as nil risks.
- The current implementation is optimized for precision, not full coverage. It will stay conservative when it cannot prove a bounded safe or risky path.
- Large-repository performance work such as global AST caching, incremental PR analysis, and concurrency is planned, but not part of this release. For now, module-scale or file-scale trials are the recommended rollout path.
- Source-tree or editable-install usage is the supported path. The default adjudicator skill is bundled as package data, but the vendored Lua grammar build still relies on this repository checkout.
- The built-in docs under `docs/` cover prompt structure and sink rule semantics in more detail.
