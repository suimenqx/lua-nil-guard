# Offline Classification

Use this path when the agent cannot be invoked from the current environment.

Typical cases:

- the provider only runs inside an internal network
- the binary is unavailable on the current machine
- credentials or routing are not ready yet
- policy allows reading docs but not executing the CLI

## Goal

Decide one of three outcomes before any runtime edits:

- `direct-fit`: the provider can likely reuse an existing protocol and should move to manifest creation
- `insufficient-evidence`: not enough facts are known yet
- `needs-runtime-changes`: current runtime cannot directly host the provider

## Minimum Facts to Collect

Capture these from documentation, copied help text, or screenshots:

1. Prompt transport
2. Output transport
3. If output is wrapped, the exact field name
4. If output is structured, the exact field name
5. Whether model selection exists
6. Whether config overrides exist

If prompt transport or output transport is unknown, stop and return `insufficient-evidence`.

## Current Direct-Fit Rules

### `schema_file_cli`

Direct fit when:

- prompt mode is `stdin`
- output mode is `schema_file`

### `stdout_envelope_cli`

Direct fit when:

- prompt mode is `flag_arg`
- output mode is `stdout_envelope`
- envelope field is exactly `response`

If the envelope field differs, plan runtime changes. The current backend does not accept arbitrary envelope field names by manifest.

### `stdout_structured_cli`

Direct fit when:

- prompt mode is `positional`
- output mode is `top_level_json`

or:

- prompt mode is `positional`
- output mode is `stdout_structured`
- structured field is `structured_output` or `result`

If the structured field differs, plan runtime changes. The current backend only recognizes the built-in field set.

## What Not to Do

- Do not claim a provider is supported only because it "returns JSON"
- Do not invent a manifest before transport facts are known
- Do not edit Lua nil-review logic to solve a backend transport mismatch
