# Plan 3: Preprocessor Macro Dictionary Integration

## 1. Purpose

This plan turns the design in [internal/preprocessor-macro-dictionary-design.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/preprocessor-macro-dictionary-design.md) into an implementation roadmap.

The immediate product goal is narrow and practical:

- stop million-line macro dictionary files from being scanned as ordinary business Lua
- still use those files to provide compile-time non-nil facts
- preserve original-source review and stable diagnostics

This is a customer pain relief plan, not a speculative architecture rewrite.

## 2. Problem Recap

Some customer repositories contain giant `.lua` files that are not normal runtime Lua modules.
They serve as compile-time replacement dictionaries:

- `NAME = "literal"`
- `COUNT = 0`
- `Defaults.Name = ""`

The customer's build system rewrites source code by replacing matching symbols with these values.

If these files are excluded:

- business files lose macro context
- false positives increase

If these files are included as ordinary review files:

- they are scanned for candidates
- they are summarized like logic code
- they are repeatedly loaded and processed
- performance and memory usage can become unacceptable

## 3. Product Principles

All implementation decisions in this plan must satisfy these principles:

1. Review the source users actually edit.
2. Do not rewrite source text before analysis.
3. Treat macro dictionary files as preprocessor inputs, not ordinary Lua review targets.
4. Stay deterministic and bounded.
5. When uncertain, remain conservative instead of guessing.

If implementation work starts to drift away from these principles, stop and re-read:

- [internal/core-nil-hazard-product-direction.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/core-nil-hazard-product-direction.md)
- [internal/preprocessor-macro-dictionary-design.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/preprocessor-macro-dictionary-design.md)

## 4. Scope

### In Scope

- file-role separation for preprocessor dictionary files
- bounded parsing of simple macro-definition lines
- a structured `MacroIndex`
- static-analysis consumption of known macro facts
- CLI/debug visibility into parsed and unparsed macro lines

### Out of Scope

- full build-system emulation
- full macro expansion of source files
- arbitrary expression evaluation
- support for every possible legacy preprocessor syntax
- runtime execution of macro dictionaries

## 5. Deliverables

By the end of `plan3`, the project should have:

1. Config support for explicit preprocessor dictionary files.
2. Repository bootstrap that separates `review_lua_files` from `preprocessor_files`.
3. A bounded macro parser that can safely parse simple literal and alias assignments.
4. A `MacroIndex` that records normalized symbol/path facts and their source locations.
5. Static analysis that consults `MacroIndex` for high-value nil-risk checks.
6. Operator-facing audit output for parsed vs unresolved macro lines.
7. Tests proving the customer's giant macro-file scenario is handled without scanning it as ordinary logic code.

## 6. Execution Phases

### Phase P1: File Role Separation

#### Objective

Stop treating macro dictionary files as ordinary review targets.

#### Required Changes

1. Extend repository configuration to support one of:
   - `preprocessor_files`
   - `preprocessor_globs`

2. Update bootstrap logic so repository state distinguishes:
   - `review_lua_files`
   - `preprocessor_files`

3. Ensure ordinary review commands (`scan`, `report`, `report-file`, `proposal-*`, `benchmark`) only iterate `review_lua_files` for candidate collection.

4. Keep `preprocessor_files` available in the snapshot for later preprocessing, but never generate ordinary candidate cases from them.

#### Acceptance Criteria

- A configured macro dictionary file produces zero ordinary review candidates.
- Existing ordinary repository review behavior remains unchanged for non-preprocessor Lua files.
- Single-file review still works when the file under review depends on macro values.

#### Test Coverage

Add tests for:

- bootstrap classifies configured preprocessor files correctly
- `review_repository()` skips candidate generation for preprocessor files
- `run_file_review()` still scans the target file while keeping macro files available as context inputs

### Phase P2: Minimal Macro Parser

#### Objective

Introduce a deterministic parser for non-standard macro dictionary files.

#### Required Changes

1. Add a new parser module dedicated to macro dictionary lines.

2. Support only bounded assignment forms in v1:
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

3. Normalize keys:
   - `NAME`
   - `Defaults.Name`

4. Record unresolved lines instead of guessing unsupported syntax.

#### Data Model

Add structured models for:

- `MacroFact`
- `MacroIndex`
- `MacroAuditResult`

Each fact should include:

- normalized key
- kind
- resolved non-nil status
- source file
- source line

#### Acceptance Criteria

- A macro dictionary file with supported assignment lines can be parsed without Tree-sitter.
- Unsupported lines are not guessed; they are recorded as unresolved.
- Alias facts are preserved as aliases even if not yet fully resolved.

#### Test Coverage

Add tests for:

- string literal parsing
- number literal parsing
- empty table parsing
- dotted-path parsing
- simple alias parsing
- unsupported expression parsing is recorded as unresolved
- comments and blank lines are safely ignored

### Phase P3: MacroIndex Resolution

#### Objective

Turn parsed macro facts into something static analysis can consume directly.

#### Required Changes

1. Build a `MacroIndex` during repository bootstrap or an early preprocessing step.

2. Support bounded alias resolution:
   - resolve direct aliases when the target is a known literal fact
   - stop when chains become cyclic, too deep, or unknown

3. Expose lookup helpers:
   - identifier lookup
   - dotted-path lookup

4. Make sure lookup returns structured fact types, not just raw strings.

#### Acceptance Criteria

- `MacroIndex` can answer whether a symbol/path is provably non-nil.
- Simple aliases resolve deterministically.
- Cycles or unsupported alias chains fail closed.

#### Test Coverage

Add tests for:

- direct alias to string literal
- direct alias to number literal
- alias to dotted path
- unknown alias target remains unresolved
- cyclic alias detection remains conservative

### Phase P4: Static Analysis Integration

#### Objective

Use macro facts to reduce false positives in the most valuable nil-hazard checks.

#### Initial Integration Targets

Only integrate `MacroIndex` into these high-value checks in v1:

1. string-library first argument sinks
   - `string.find`
   - `string.match`
   - `string.gsub`
   - `string.sub`
   - `string.len`
   - `string.byte`
   - `string.lower`
   - `string.upper`

2. string concatenation `..`

3. table iteration
   - `pairs`
   - `ipairs`

4. length operator
   - `#`

5. numeric ordering comparisons
   - `<`
   - `<=`
   - `>`
   - `>=`

6. numeric arithmetic
   - `+`
   - `-`
   - `*`
   - `/`
   - `%`
   - `^`

#### Required Changes

1. Before defaulting an identifier/path to `unknown`, query `MacroIndex`.

2. If the macro fact is a known non-nil string:
   - treat it as safe for string sinks and string concatenation.

3. If the macro fact is a known non-nil number:
   - treat it as safe for numeric comparisons and arithmetic.

4. If the macro fact is a known non-nil table (including `{}`):
   - treat it as safe for `pairs`, `ipairs`, and `#`.

5. Keep all reporting tied to the original source file and location.

#### Acceptance Criteria

- A file using macro-backed identifiers no longer reports false positives when the macro value is provably non-nil.
- The same file still reports real risks when the macro value is missing or unresolved.
- No source rewriting is introduced.

#### Test Coverage

Add end-to-end tests for:

- `string.find(MACRO_STRING, ...)`
- `MACRO_STRING .. suffix`
- `pairs(MACRO_TABLE)`
- `#MACRO_TABLE`
- `MAX_LEVEL + bonus`
- `MAX_LEVEL >= threshold`

Also add negative tests:

- unresolved macro symbol should still remain risky/uncertain as appropriate
- unsupported macro syntax should not suppress risk

### Phase P5: Macro-Aware Single-File Review

#### Objective

Make sure the most likely customer workflow works:

- review one file
- use macro dictionary for compile-time facts
- do not scan the giant macro file as business logic

#### Required Changes

1. Ensure `run_file_review()` pulls in `MacroIndex` from `preprocessor_files`.

2. Ensure single-file review:
   - does not generate verdicts for macro files
   - still uses their facts when analyzing the target file

3. Make this path explicit in documentation.

#### Acceptance Criteria

- Reviewing one business file works even when the macro dictionary file is excluded from ordinary candidate scanning.
- Macro-backed values still reduce false positives.

#### Test Coverage

Add a customer-style test:

- giant macro-style file configured as preprocessor input
- business file uses macro-backed values
- target business file reviews correctly
- macro file generates no verdicts

### Phase P6: Auditability and Operator Tools

#### Objective

Make macro ingestion transparent and supportable.

#### Required Changes

1. Add a `macro-audit` command, or equivalent reporting path, that shows:
   - parsed facts
   - unresolved lines
   - counts by kind
   - source file coverage

2. Expose enough detail for support engineers:
   - which macro files were loaded
   - how many lines were recognized
   - how many were skipped

3. Update documentation to explain:
   - what macro files are
   - what syntax is supported
   - what remains unsupported in v1

#### Acceptance Criteria

- Operators can tell which compile-time facts were trusted.
- Operators can identify unresolved macro lines without reading code paths manually.

#### Test Coverage

Add tests for:

- audit output shape
- non-empty unresolved line reporting
- empty/clean macro dictionary reporting

## 7. Implementation Order

Work must proceed in this order:

1. `P1` File role separation
2. `P2` Minimal macro parser
3. `P3` MacroIndex resolution
4. `P4` Static-analysis integration
5. `P5` Macro-aware single-file review
6. `P6` Auditability and operator tools

Do not start broad static-analysis integration before `P1` and `P2` are stable.

## 8. Guardrails

To prevent scope drift:

1. Do not parse macro dictionary files with Tree-sitter.
2. Do not allow macro files to enter ordinary candidate collection.
3. Do not attempt full textual expansion of source files.
4. Do not guess unsupported macro syntax.
5. Do not let macro facts silently override ordinary source-local proofs when they conflict.

When in doubt, prefer:

- unresolved
- explicit operator visibility
- narrow support

## 9. Metrics

The plan is considered successful only if it improves both correctness and operability.

Track these indicators:

1. number of review candidates generated from configured macro files
   - target: `0`

2. macro-backed false positives removed in core nil hazards
   - target: measurable reduction in customer fixture cases

3. parse success ratio for configured macro files
   - target: high for supported syntax; unresolved lines clearly reported

4. single-file review wall-clock behavior on repositories with giant macro files
   - target: no pathological growth from scanning macro files as ordinary business code

## 10. Recommended First Acceptance Fixture

Before calling `plan3` complete, build and keep one representative acceptance fixture that mirrors the reported customer problem:

1. one giant macro-style file with:
   - strings
   - numbers
   - empty tables
   - simple aliases

2. one ordinary business file that uses those symbols in:
   - `string.find`
   - `..`
   - `pairs`
   - `#`
   - arithmetic
   - comparison

3. one unresolved macro line to prove the system remains conservative

Success means:

- the macro file is not scanned as ordinary business code
- the business file receives macro-backed proof improvements
- unresolved macro syntax does not produce false safety

## 11. Exit Criteria

`plan3` is complete only when all of the following are true:

1. Macro dictionary files are role-separated from ordinary review files.
2. A bounded macro parser exists and is tested.
3. `MacroIndex` is integrated into the highest-value nil hazard checks.
4. Single-file review benefits from macro facts without scanning the macro file as logic.
5. Operators can audit what was parsed and what was ignored.
6. The customer-style acceptance fixture passes.
7. Full automated test suite passes.

## 12. After Plan 3

Only after `plan3` is complete should the project consider broader enhancements such as:

- richer table literal parsing
- chained macro alias resolution beyond the bounded first version
- path-pattern macro support
- selective integration into more advanced static proof systems

The first objective is not to become a full preprocessor. The first objective is to stop treating a giant preprocessor dictionary as ordinary business Lua while preserving valuable compile-time facts.
