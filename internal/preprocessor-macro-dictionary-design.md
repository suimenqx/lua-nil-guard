# Preprocessor Macro Dictionary Design

## Problem Statement

Some customer repositories contain very large `.lua` files that are not normal runtime Lua modules.
They act as compile-time replacement dictionaries:

- each line defines a symbol or dotted path on the left-hand side
- the right-hand side is a literal, a table-like default, or a simple alias
- during the build pipeline, source code is rewritten by replacing matching symbols with these values

These files create a hard product problem:

- if they are excluded from review, ordinary source files lose macro/default-value context and produce false positives
- if they are included as ordinary Lua files, the current pipeline scans, summarizes, and indexes them like business code, which can cause severe latency, high memory usage, or apparent hangs

The key insight is:

**These files are not ordinary Lua review targets. They are preprocessor dictionaries.**

The scanner should continue to review the original pre-expanded source, but it should consume compile-time value facts from these dictionary files.

## Goals

- Preserve original-source review as the authoritative scan target
- Eliminate the need to treat macro dictionary files as ordinary review candidates
- Extract stable, bounded compile-time value facts from non-standard macro files
- Reduce false positives caused by missing default values or known non-nil constants
- Prevent pathological performance and memory blowups caused by scanning giant data-only files

## Non-Goals

- Do not implement a full Lua interpreter
- Do not fully emulate the customer's build-time preprocessor
- Do not rewrite source files before scanning
- Do not rely on Tree-sitter for non-standard macro files
- Do not infer complex dynamic macro semantics in the first version

## Core Model

Introduce a new first-class concept:

**Macro Dictionary / Preprocessor Symbol Table**

This is separate from ordinary repository Lua files.

It is:

- loaded before review
- parsed by a dedicated bounded parser
- converted into a `MacroIndex`
- consulted during static analysis

It is not:

- scanned for sink candidates
- summarized as business logic
- included in verdict generation as a normal Lua file

## Architecture

### 1. File Role Split

Repository inputs should be split into at least two categories:

- `review_lua_files`: ordinary Lua files to scan and adjudicate
- `preprocessor_files`: macro dictionary files that provide compile-time facts only

Recommended configuration field:

```json
{
  "preprocessor_files": [
    "src/macros.lua",
    "src/default_values.lua"
  ]
}
```

Or a glob-based variant:

```json
{
  "preprocessor_globs": [
    "build/preprocess/**/*.lua",
    "legacy/defaults/*.lua"
  ]
}
```

These files should be resolved during repository bootstrap, but excluded from ordinary candidate scanning.

### 2. Dedicated Macro Parser

Do not parse macro dictionary files with the ordinary Lua parser pipeline.

Instead, implement a bounded line-oriented parser that supports only stable, explicit assignment forms.

First-version supported forms:

- `NAME = "literal"`
- `NAME = 'literal'`
- `NAME = 123`
- `NAME = 1.23`
- `NAME = {}`
- `NAME = OTHER_NAME`
- `PATH.NAME = "literal"`
- `PATH.NAME = 0`
- `PATH.NAME = {}`
- `PATH.NAME = OTHER_NAME`

Optional later extension:

- flat table literals with simple fields
- chained aliases
- more permissive whitespace and comment handling

Unsupported forms in the first version should be ignored and recorded as unresolved macro lines, not guessed.

### 3. MacroIndex

The macro parser should produce a structured `MacroIndex`.

Conceptually:

```json
{
  "USER_NAME_DEFAULT": {
    "kind": "string",
    "value": ""
  },
  "MAX_LEVEL": {
    "kind": "number",
    "value": 100
  },
  "Defaults.Name": {
    "kind": "string",
    "value": ""
  },
  "DEFAULT_ALIAS": {
    "kind": "alias",
    "target": "USER_NAME_DEFAULT"
  }
}
```

Each record should at minimum carry:

- normalized symbol/path
- resolved kind
- whether it is provably non-nil
- whether it is a literal, table, or alias
- source file and line for auditability

Recommended kinds:

- `string_literal`
- `number_literal`
- `boolean_literal`
- `empty_table`
- `alias`
- `unknown`

## Review Semantics

### Review Target Remains Original Source

The scanner should continue to analyze the original pre-expanded source files.

That means:

- case IDs stay tied to original source locations
- line/column references stay stable
- user-facing diagnostics point to code the user actually edits

### MacroIndex Is Consulted During Analysis

When static analysis sees a symbol or dotted path, it should consult the `MacroIndex` before defaulting to `unknown`.

Examples:

- `string.find(USER_NAME_DEFAULT, ...)`
  - if `USER_NAME_DEFAULT = ""`, treat arg1 as provably non-nil

- `pairs(DEFAULT_TABLE)`
  - if `DEFAULT_TABLE = {}`, treat the table operand as provably non-nil

- `#Defaults.Items`
  - if `Defaults.Items = {}`, treat the operand as provably non-nil

- `MAX_LEVEL + bonus`
  - if `MAX_LEVEL = 0`, the left operand should not be treated as maybe nil

### No Source Rewriting in the First Version

Do not perform textual macro expansion before scanning.

Instead:

- keep the original source intact
- perform symbol-level semantic lookup against the `MacroIndex`

This avoids:

- source-location drift
- confusing user-facing diagnostics
- accidental semantic corruption from naive text substitution

## Why This Is Better Than Context-Only Files

`context_only` is better than scanning giant data files as ordinary business code, but it still assumes those files are some form of valid Lua context file.

That assumption is wrong for this scenario.

These files are:

- not standard Lua
- not business logic
- not reliable Tree-sitter inputs

So the better abstraction is not:

- "a special kind of Lua file"

It is:

- "a preprocessor dictionary consumed by a separate preprocessing layer"

## Implementation Phases

### Phase P1: File Role Separation

- add `preprocessor_files` / `preprocessor_globs` config support
- classify files at bootstrap
- exclude preprocessor files from ordinary `review_repository()` candidate scanning

Exit criteria:

- a configured macro dictionary file no longer generates ordinary review candidates
- repository review remains correct for normal Lua files

### Phase P2: Minimal Macro Parser

- implement a deterministic line parser for bounded assignment forms
- ignore unsupported lines safely
- produce a `MacroIndex`

Exit criteria:

- a macro file with simple literal assignments can be ingested without Tree-sitter
- unsupported lines are reported as unknown, not guessed

### Phase P3: Static Analysis Integration

- consult `MacroIndex` during local symbol/path reasoning
- treat known macro literals as strong non-nil facts where appropriate
- reduce false positives in core hazard sinks

Exit criteria:

- string, concat, pairs/ipairs, `#`, and arithmetic/comparison risks respect known macro values

### Phase P4: Auditability and Debugging

- add reporting of macro source line origins
- optionally add a `macro-audit` CLI command
- expose unresolved macro lines for operator review

Exit criteria:

- operators can understand which macro facts were trusted and which were ignored

## Failure Policy

The macro layer must remain conservative.

If a macro line cannot be safely understood:

- do not guess
- do not silently rewrite semantics
- leave the symbol unresolved
- keep the corresponding review path conservative

This preserves the project's precision-first stance.

## Recommended First Version Scope

The best first version is intentionally narrow:

1. support explicit `preprocessor_files`
2. parse only simple top-level assignments
3. support literals and simple aliases
4. integrate `MacroIndex` only into the most valuable nil-risk checks

This is enough to solve the current customer pain:

- avoid scanning a million-line macro dictionary as business code
- still import its non-nil defaults into review reasoning

## Product Positioning Impact

This design keeps the product aligned with real enterprise build pipelines:

- review the source users maintain
- understand the compile-time value layer without pretending it is ordinary Lua
- reduce false positives without sacrificing explainability

The scanner becomes more correct because it understands a real part of the customer's build model, not because it scans more text.

## One-Sentence Summary

The correct solution is to treat the giant non-standard `.lua` macro file as a **preprocessor dictionary**, not as a normal review target: keep scanning the original source, but add a preprocessing layer that builds a bounded `MacroIndex` and feeds compile-time value facts into static analysis.
