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

`init-config` writes the default versions of both files into the target repository. You can edit them afterward to match project-specific rules or confidence policy.

## Notes

- Source-tree or editable-install usage is the supported path. The default skill file is loaded from this repository checkout.
- The built-in docs under `docs/` cover prompt structure and sink rule semantics in more detail.
