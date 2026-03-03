# Lua Nil Review Agent

`lua-nil-review-agent` is a developer-facing CLI for reviewing Lua code for likely nil-related runtime faults. The supported operating model is source-tree usage: keep this repository intact, run from the checkout, and point the tool at Lua repositories you want to inspect.

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

`init-config` writes the default versions of all three files into the target repository. `function_contracts.json` lets you declare high-confidence wrapper functions such as `normalize_name` that always return a non-nil value, helper guards such as `assert_profile(profile)` via `ensures_non_nil_args`, and normalizers that return a defaulted non-nil value from specific arguments via `returns_non_nil_from_args`. You can also restrict a contract to specific caller modules with `applies_in_modules`, to specific caller function scopes with `applies_in_function_scopes`, to scope kinds with `applies_to_scope_kinds` (`top_level`, `function_body`), to top-level phases with `applies_to_top_level_phases` (`init`, `post_definitions`), to specific sink rules or sink names with `applies_to_sinks`, to specific call positions with `applies_to_call_roles` (`assignment_origin`, `sink_expression`, `guard_call`), to specific return-value usage modes with `applies_to_usage_modes` (`single_assignment`, `multi_assignment`, `direct_sink`), to specific selected return slots with `applies_to_return_slots` (for example only return slot `1` in a multi-return helper), to a specific call arity with `applies_with_arg_count`, to exact literal arguments with `required_literal_args`, to argument-source shapes with `required_arg_shapes` (`identifier`, `member_access`, `indexed_access`, `literal`, `call`, `expression`), to argument root symbols with `required_arg_roots` (for example `req`, `ngx`, or `fallbacks`), to dotted access-path prefixes with `required_arg_prefixes` (for example `req.params` or `ngx.var`), and to exact normalized access chains with `required_arg_access_paths` (for example `req.params.user` or `req.params[1]`) when a helper is only trustworthy for one exact lookup path. Quoted literal table keys such as `req.params["user"]` normalize to the same `req.params.user` path, while dynamic indexes such as `req.params[token]` do not count as an exact match. This helps suppress false positives without relying on prompt-only inference.

## Notes

- Source-tree or editable-install usage is the supported path. The default skill file is loaded from this repository checkout.
- The built-in docs under `docs/` cover prompt structure and sink rule semantics in more detail.
