# Sink Rule Catalog

## Purpose

`config/sink_rules.json` is the canonical catalog for nil-sensitive sinks.

Each rule describes:

- which API or operation is dangerous
- which argument or receiver is nil-sensitive
- how the failure manifests
- which safe patterns may suppress a finding

## Current Schema

Each item is a JSON object with:

- `id`: stable unique identifier
- `kind`: rule type, such as `function_arg` or `receiver`
- `qualified_name`: callable or synthetic operation name
- `arg_index`: 1-based argument index, or `0` for receiver-like access
- `nil_sensitive`: whether nil is disallowed
- `failure_mode`: expected failure mode
- `default_severity`: default severity label
- `safe_patterns`: known local suppression patterns

## Authoring Rules

When adding rules:

1. Keep `id` stable and unique.
2. Prefer precise rules over broad catch-all entries.
3. Add only patterns that are broadly safe within this repository.
4. Add tests if the schema or loader behavior changes.

## Extension Strategy

Add new rules in this order:

1. Built-in Lua and standard-library sinks
2. Repository-wide wrappers with well-understood behavior
3. Framework-specific helpers after they are observed in real code

Avoid adding speculative rules that lack a clear runtime failure model.
