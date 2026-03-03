---
name: agent-backend-onboarding
description: Onboard new CLI-based agent backends into this lua-nil-review-agent repository with minimal manual branching. Use when adding a new provider, probing a new agent CLI, deciding whether it fits schema_file_cli, stdout_envelope_cli, or stdout_structured_cli, classifying whether a provider can directly integrate in restricted or offline environments, generating a provider manifest, validating runtime compatibility, smoke-testing report or benchmark flows, or scaffolding the exact code touchpoints for a new protocol.
---

# Agent Backend Onboarding

Use this skill when extending this repository to support another agent backend.

Keep the existing architecture intact:

- provider behavior lives in a manifest
- transport behavior lives in a protocol
- runtime creation lives in the backend registry

Prefer the smallest possible change set. Reuse an existing protocol unless the new agent truly needs a new transport shape.

## Workflow

1. Gather concrete CLI facts before editing code.
Run the provider's `--help` and a smallest non-interactive probe first when the environment allows it.

If the environment cannot execute the provider, collect documented transport facts instead and use the offline classification path before writing any runtime code.

Confirm these facts:

- how the prompt is passed: stdin, flag argument, or positional argument
- how the model is selected
- whether config overrides exist
- whether the CLI can emit JSON
- where the structured payload actually appears: file, top-level stdout JSON, or a field inside an envelope
- whether a cold-start warm-up is needed for stability

## Offline Classification Path

Use this path when the provider cannot be invoked yet, such as an internal-network-only agent or a CLI unavailable in the current environment.

Classify transport fit from observed or documented behavior first:

```bash
python3 skills/agent-backend-onboarding/scripts/classify_provider_fit.py \
  my-agent \
  --prompt-mode flag_arg \
  --output-mode stdout_envelope \
  --envelope-field response
```

Read [references/offline-classification.md](references/offline-classification.md) if you only have docs, screenshots, or copied `--help` output.

Use the classification result like this:

- `status = direct-fit`: generate a manifest and defer only the live smoke test
- `status = insufficient-evidence`: stop and gather the missing transport facts
- `status = needs-runtime-changes`: do not claim direct support; plan a protocol/backend extension first

2. Reuse an existing protocol when possible.
Read [references/protocol-selection.md](references/protocol-selection.md) if the fit is not obvious.

Only add a new protocol when the existing runtime cannot describe the transport shape.

3. Create a provider manifest before touching runtime code.
Use `scripts/generate_provider_manifest.py` to create a valid starting manifest.

Example:

```bash
python3 skills/agent-backend-onboarding/scripts/generate_provider_manifest.py \
  my-agent stdout_envelope_cli \
  --executable my-agent \
  --output /tmp/my-agent.json
```

If the provider is experimental, keep the manifest outside `src/` and use `--backend-manifest` from the CLI.

If the provider should become built in, copy the generated payload into `src/lua_nil_review_agent/agent_driver_manifest.py`.

4. Validate the runtime registration path before claiming support.
Run these in order:

- `python3 -m lua_nil_review_agent validate-backend-manifest <manifest>`
- `python3 -m lua_nil_review_agent validate-backend-manifest-json <manifest>`
- `python3 -m lua_nil_review_agent register-backend-manifest --replace <manifest>`

If runtime compatibility fails, stop and fix the protocol choice before touching review logic.

5. Smoke-test the provider on review flows.
Prefer a smallest explicit-nil positive case first, then benchmark.

Recommended commands:

```bash
python3 -m lua_nil_review_agent report-json \
  --backend my-agent \
  --backend-manifest /tmp/my-agent.json \
  examples/mvp_cases/agent_semantic_suite

python3 -m lua_nil_review_agent benchmark-json \
  --backend my-agent \
  --backend-manifest /tmp/my-agent.json \
  examples/mvp_cases/agent_semantic_suite
```

Check:

- whether the backend can be created
- whether the provider times out or falls back
- whether benchmark accuracy is acceptable
- whether warm-up cost is hiding a review-path problem

6. Add new runtime code only when manifest plus protocol reuse is insufficient.
Read [references/runtime-touchpoints.md](references/runtime-touchpoints.md) before editing code.

If a new protocol is required, keep the change local to:

- `src/lua_nil_review_agent/agent_protocols.py`
- `src/lua_nil_review_agent/agent_backend.py`
- `src/lua_nil_review_agent/agent_driver_manifest.py` if the provider becomes built in
- targeted tests first, then full tests

Do not change Lua adjudication logic when the task is only backend onboarding.

## Done Criteria

Treat the onboarding as complete only when all of these are true:

- the manifest validates
- the backend registers and can be instantiated
- `report-json` or `benchmark-json` completes on a smoke fixture
- protocol choice is documented or the new protocol is covered by tests
- repository tests pass

## Resources

- `scripts/generate_provider_manifest.py`: create a valid provider manifest with protocol-aligned defaults
- `scripts/classify_provider_fit.py`: classify whether a provider can directly reuse an existing runtime protocol without invoking it
- [references/protocol-selection.md](references/protocol-selection.md): decide whether an existing protocol fits
- [references/offline-classification.md](references/offline-classification.md): classify direct-fit viability when the provider cannot be executed yet
- [references/runtime-touchpoints.md](references/runtime-touchpoints.md): exact files and tests to touch when manifest-only onboarding is not enough
