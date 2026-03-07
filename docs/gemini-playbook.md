# Gemini Backend Playbook

This guide is a practical, follow-along playbook for using Gemini as the Lua nil-risk adjudication backend.

It also covers how to configure a new custom backend and how to pin a model.

## 1. Quick Start (Gemini)

1. Verify local toolchain and parser:

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

4. Benchmark with JSON output (recommended for tuning):

```sh
lua-nil-guard benchmark-json \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/labeled-repo \
  build/benchmark_gemini.json
```

Labeled files must follow: `provable_risky_*`, `provable_safe_*`, or `provable_uncertain_*`.

## 2. Backend and Model Selection

`lua-nil-guard` backend/model switches:

- `--backend <name>`: choose adjudication backend (for example `gemini`, `codex`, `claude`).
- `--model <model_id>`: override backend model when the backend supports model overrides.
- `--backend-executable <path>`: override CLI binary path for that run.
- `--backend-timeout <seconds>`: request timeout per backend call.
- `--backend-attempts <n>`: retry attempts per backend call.
- `--backend-config KEY=VALUE`: backend-specific config overrides (only when provider supports it).

Examples:

```sh
lua-nil-guard report --backend gemini --model gemini-3.1-pro-preview /path/to/target-repo
lua-nil-guard report --backend codex --model gpt-5.1-codex-mini /path/to/target-repo
lua-nil-guard report --backend claude --model claude-sonnet-4-5 /path/to/target-repo
```

Notes:

- If `--model` is omitted for `gemini`, current default is `gemini-3.1-pro-preview`.
- If a provider does not support model override and you pass `--model`, the command fails with `does not support model overrides`.

## 3. Configure a New Backend (Custom Provider)

### 3.1 Pick a protocol

Supported manifest protocols:

- `schema_file_cli`: CLI reads schema/output files.
- `stdout_structured_cli`: CLI prints structured JSON envelope to stdout.
- `stdout_envelope_cli`: CLI prints JSON envelope to stdout from prompt args.

### 3.2 Generate a starter manifest

```sh
lua-nil-guard generate-backend-manifest myagent stdout_envelope_cli build/myagent.manifest.json
```

### 3.3 Edit manifest fields

Minimal example:

```json
{
  "name": "myagent",
  "protocol": "stdout_envelope_cli",
  "default_executable": "myagent-cli",
  "default_timeout_seconds": 90.0,
  "default_max_attempts": 2,
  "default_fallback_to_uncertain_on_error": true,
  "default_expanded_evidence_retry_mode": "auto",
  "capabilities": {
    "supports_model_override": true,
    "supports_config_overrides": false,
    "supports_backend_cache": true,
    "supports_output_schema": false,
    "supports_output_file": false,
    "supports_stdout_json": true,
    "supports_tool_free_prompting": true
  }
}
```

### 3.4 Validate manifest

```sh
lua-nil-guard validate-backend-manifest build/myagent.manifest.json
```

### 3.5 Use it in review commands

One-off (manifest provided inline):

```sh
lua-nil-guard report \
  --backend myagent \
  --backend-manifest build/myagent.manifest.json \
  --model myagent-pro \
  /path/to/target-repo
```

Persistent registration (for repeated runs):

```sh
lua-nil-guard register-backend-manifest --replace build/myagent.manifest.json
lua-nil-guard report --backend myagent --model myagent-pro /path/to/target-repo
```

Important:

- `--backend` must match manifest `name`.
- If `supports_model_override` is `false`, do not pass `--model`.
- If `supports_config_overrides` is `false`, do not pass `--backend-config`.

## 4. Practical Gemini Tuning

Use this baseline first:

- `--backend-timeout 90`
- `--backend-attempts 1`

When fallback/errors appear:

1. Check `cases[*].backend_failure_reason` in benchmark JSON.
2. If transport errors like `ERR_STREAM_PREMATURE_CLOSE` appear, increase `--backend-attempts` to `2` or `3`.
3. If many cases time out, raise timeout to `120`.

Observed on `examples/mvp_cases/agent_semantic_suite` (2026-03-07):

- `--backend-timeout 25 --backend-attempts 1`: heavy fallback and degraded accuracy.
- `--backend-timeout 90 --backend-attempts 1`: `17/18` exact matches (`94.4%`), one transient backend failure.
