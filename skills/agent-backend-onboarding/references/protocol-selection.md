# Protocol Selection

Use the smallest existing protocol that matches the provider's transport shape.

## Existing Protocols

### `schema_file_cli`

Use this when the CLI:

- accepts a schema file path
- writes the result to an output file
- optionally accepts a working directory flag

This is the `codex` shape. Reuse it when the provider can be treated as "schema in, file out".

### `stdout_envelope_cli`

Use this when the CLI:

- prints JSON to stdout
- expects the prompt as a flag argument
- places the real adjudication payload inside a string field such as `response`

This is the `codeagent` shape. Reuse it when stdout is a JSON envelope and the verdict must be unwrapped from a string.

### `stdout_structured_cli`

Use this when the CLI:

- prints JSON to stdout
- accepts the prompt as a positional argument after `--`
- returns a structured payload directly in a field such as `structured_output` or `result`

This is the `claude` shape. Reuse it when stdout already contains machine-readable fields and only a shallow unwrap is needed.

## Choose an Existing Protocol First

Prefer manifest-only onboarding when the new provider differs only by:

- executable name
- timeout or retry defaults
- capability flags
- model flag support
- config override support

These differences belong in the provider manifest, not a new protocol.

## Add a New Protocol Only When

Add a new protocol when at least one of these is true:

- the prompt transport cannot be expressed by the existing protocol builders
- the result cannot be extracted by the current backend parser for that protocol
- the provider is not CLI-based
- the provider requires a materially different request or response lifecycle

## Quick Classification Checks

Answer these before writing code:

1. Where does the prompt go?
2. Where does the structured payload come back?
3. Is the payload already JSON, or a string that must be parsed again?
4. Can existing parsing logic normalize it without special cases?
5. Are the only differences default flags and capability booleans?

If the answer to 5 is yes, stay with manifest-only onboarding.
