# Nil Guard Annotation Syntax

## Purpose

`@nil_guard` annotations allow developers to declare nil-related function contracts directly in Lua source comments. LuaNilGuard uses these annotations as high-priority evidence for cross-function nil-risk reasoning.

Annotations are optional. Unannotated functions are handled conservatively.

## Syntax

All annotations use the `--- @nil_guard` prefix inside Lua comments. Place them directly above the function definition.

### returns_non_nil

Declares that the function always returns a non-nil value.

```lua
--- @nil_guard: returns_non_nil
function get_name()
    return self.name or "unknown"
end
```

### ensures_non_nil_arg N

Declares that the function guarantees argument N is non-nil after the call (via assert, error, or guard).

```lua
--- @nil_guard: ensures_non_nil_arg 1
function assert_present(value)
    assert(value ~= nil, "expected non-nil")
    return value
end
```

### param NAME: non_nil | may_nil

Declares the nil-ability of a specific parameter.

```lua
--- @nil_guard param raw: may_nil
--- @nil_guard param fallback: non_nil
function normalize(raw, fallback)
    return raw or fallback or ""
end
```

### return SLOT: non_nil | may_nil

Declares the nil-ability of a specific return slot.

```lua
--- @nil_guard return 1: non_nil
function get_count()
    return self.count or 0
end
```

### Conditional returns

Declares that the return value is non-nil only under a specific condition.

```lua
--- @nil_guard: returns_non_nil when arg1 is non_nil
function normalize_name(raw)
    return raw or ""
end
```

## Multiple annotations

Multiple annotations can be placed above the same function:

```lua
--- @nil_guard param raw: may_nil
--- @nil_guard return 1: non_nil
function normalize(raw)
    return raw or ""
end
```

## Consistency verification

LuaNilGuard verifies that annotations are consistent with the function body. Inconsistent annotations (e.g., declaring `returns_non_nil` when the function has a `return nil` path) are flagged and not trusted for cross-function reasoning.

## Priority

```
annotation > function_contracts.json > bounded static recognizer > LLM adjudication
```

Annotations take priority over `function_contracts.json` entries. If a function has both an annotation and a contract, the annotation is used. `function_contracts.json` remains as a fallback for repositories that do not use annotations.

## CLI commands

- `lua-nil-guard annotation-coverage <repository>` — Show annotation coverage by module.
- `lua-nil-guard annotation-suggest <file.lua>` — Suggest annotations based on static analysis.
