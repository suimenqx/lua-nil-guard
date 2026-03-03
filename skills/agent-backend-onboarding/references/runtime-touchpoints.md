# Runtime Touchpoints

Use this file when manifest-only onboarding is not enough and the repository needs runtime changes.

## Manifest-Only Path

If an existing protocol fits, the normal path is:

1. Generate a manifest
2. Validate it with the CLI
3. Load it with `--backend-manifest` or register it with `register-backend-manifest`
4. Smoke-test review commands

Do not edit runtime code in this path.

## Files to Touch for a New Protocol

### `src/lua_nil_review_agent/agent_protocols.py`

Add the command builder for the new transport shape and register it in `CLI_PROTOCOL_BUILDERS`.

### `src/lua_nil_review_agent/agent_backend.py`

Add or extend the backend class that can execute the new protocol and normalize the provider response into `AdjudicationRecord`.

Keep changes local to transport, parsing, retry, fallback, cache, and metrics behavior.

### `src/lua_nil_review_agent/agent_driver_manifest.py`

Only edit this when the provider should become built in. External providers can stay manifest-only.

### `src/lua_nil_review_agent/cli.py`

Only edit this when user-facing flags or built-in backend names change. Do not change CLI help for manifest-only onboarding.

## Tests to Update First

Start with targeted tests:

- `tests/test_agent_protocols.py`
- `tests/test_cli_agent_backend.py`
- `tests/test_agent_driver_manifest.py`
- `tests/test_cli.py` when CLI behavior changes

Then run the full suite.

## Required Validation Sequence

Use this order:

1. `python3 -m lua_nil_review_agent validate-backend-manifest-json <manifest>`
2. `python3 -m lua_nil_review_agent benchmark-json --backend <name> --backend-manifest <manifest> <fixture>`
3. `pytest -q tests/test_agent_protocols.py tests/test_cli_agent_backend.py`
4. `pytest -q`

## Review Discipline

- Preserve the `manifest + protocol + registry` split.
- Prefer extending the narrowest layer possible.
- Do not change Lua nil-review semantics for backend onboarding work.
- When adding a built-in provider, keep external manifest loading working exactly as before.
