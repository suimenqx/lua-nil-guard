# LuaNilGuard

`LuaNilGuard` is the project name. The current CLI command remains `lua-nil-review-agent`.

`lua-nil-review-agent` is a developer-facing CLI for reviewing Lua code for likely nil-related runtime faults. The supported operating model is source-tree usage: keep this repository intact, run from the checkout, and point the tool at Lua repositories you want to inspect.

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

3. Initialize the target repository config:

```sh
lua-nil-review-agent init-config /path/to/target-repo
```

4. Run a static scan:

```sh
lua-nil-review-agent scan /path/to/target-repo
```

5. Run a full report:

```sh
lua-nil-review-agent report /path/to/target-repo
```

## Single-File Review

If you only want to inspect one Lua file, use the file entrypoints. The file still needs to live inside a repository that has been initialized with `init-config`.

```sh
lua-nil-review-agent scan-file /path/to/target-repo/src/demo.lua
lua-nil-review-agent report-file /path/to/target-repo/src/demo.lua
lua-nil-review-agent report-file-json /path/to/target-repo/src/demo.lua
```

Single-file review keeps repository context, so cross-file function summaries and related function source snippets can still be used during adjudication.

## Recommended First Run

For a first trial, do not start with a full repository scan. Start with one representative Lua file, then tighten configuration only if the result is too uncertain.

1. Initialize the target repository once:

```sh
lua-nil-review-agent init-config /path/to/target-repo
```

2. Pick one real file with a known nil-sensitive call and run:

```sh
lua-nil-review-agent report-file /path/to/target-repo/src/demo.lua
```

3. If the result is already `risky` or `safe`, keep iterating on small files before moving to a wider scan.

4. If the result is mostly `uncertain`, check whether the file depends on helper functions that are not defined in the current repository checkout. In that case, add a narrow contract to `config/function_contracts.json` instead of widening the scan immediately.

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

5. Re-run the same file after updating contracts. Only after a few representative files behave well should you move on to:

```sh
lua-nil-review-agent report /path/to/target-repo
```

6. If you want to see what the tool still cannot prove, inspect the proposal backlog:

```sh
lua-nil-review-agent proposal-analytics /path/to/target-repo
```

This report is most useful after you have already tried a few single-file runs. It helps separate:

- truly unresolved patterns that may need new bounded recognizers
- helper functions that may need an explicit contract

## Backends

The default backend is `heuristic`. For LLM-backed adjudication, use `--backend` with one of the supported local CLI integrations:

- `gemini`
- `codeagent`
- `claude`
- `codex`

Examples:

```sh
lua-nil-review-agent report --backend gemini /path/to/target-repo
lua-nil-review-agent report-file --backend codeagent /path/to/target-repo/src/demo.lua
```

Those backends require the corresponding local CLI tool, credentials, and network access to already be working on the machine. For custom providers, generate a starter manifest with:

```sh
lua-nil-review-agent generate-backend-manifest my-provider stdout_envelope_cli
```

## Repository Layout

Target repositories are expected to contain:

- `config/sink_rules.json`
- `config/confidence_policy.json`
- `config/function_contracts.json`

`init-config` writes the default versions of all three files into the target repository. `function_contracts.json` lets you declare high-confidence wrapper functions such as `normalize_name` that always return a non-nil value, helper guards such as `assert_profile(profile)` via `ensures_non_nil_args`, and normalizers that return a defaulted non-nil value from specific arguments via `returns_non_nil_from_args`. For multi-return helpers you can further split those argument requirements by consumed return slot with `returns_non_nil_from_args_by_return_slot`, so slot `1` and slot `2` do not have to share the same safety preconditions. You can also require that certain input arguments have already been guarded before trusting a specific return slot by using `requires_guarded_args_by_return_slot`, which lets a guard helper contract and a later normalizer contract work together in one proof chain. You can also restrict a contract to specific caller modules with `applies_in_modules`, to specific caller function scopes with `applies_in_function_scopes`, to scope kinds with `applies_to_scope_kinds` (`top_level`, `function_body`), to top-level phases with `applies_to_top_level_phases` (`init`, `post_definitions`), to specific sink rules or sink names with `applies_to_sinks`, to specific call positions with `applies_to_call_roles` (`assignment_origin`, `sink_expression`, `guard_call`), to specific return-value usage modes with `applies_to_usage_modes` (`single_assignment`, `multi_assignment`, `direct_sink`), to specific selected return slots with `applies_to_return_slots` (for example only return slot `1` in a multi-return helper), to a specific call arity with `applies_with_arg_count`, to exact literal arguments with `required_literal_args`, to argument-source shapes with `required_arg_shapes` (`identifier`, `member_access`, `indexed_access`, `literal`, `call`, `expression`), to argument root symbols with `required_arg_roots` (for example `req`, `ngx`, or `fallbacks`), to dotted access-path prefixes with `required_arg_prefixes` (for example `req.params` or `ngx.var`), and to exact normalized access chains with `required_arg_access_paths` (for example `req.params.user` or `req.params[1]`) when a helper is only trustworthy for one exact lookup path. Quoted literal table keys such as `req.params["user"]` normalize to the same `req.params.user` path, while dynamic indexes such as `req.params[token]` do not count as an exact match. This helps suppress false positives without relying on prompt-only inference.

## Notes

- This release is intended for developer trial use. Start with a few real files or one small module before using it across a large repository.
- Single-file review works best when important helper functions are either present in the same repository or represented in `config/function_contracts.json`.
- Missing helper definitions do not block review, but they reduce cross-file proof strength and can increase `uncertain` results.
- The current implementation is optimized for precision, not full coverage. It will stay conservative when it cannot prove a bounded safe or risky path.
- Large-repository performance work such as global AST caching, incremental PR analysis, and concurrency is planned, but not part of this release. For now, module-scale or file-scale trials are the recommended rollout path.
- Source-tree or editable-install usage is the supported path. The default skill file is loaded from this repository checkout.
- The built-in docs under `docs/` cover prompt structure and sink rule semantics in more detail.
