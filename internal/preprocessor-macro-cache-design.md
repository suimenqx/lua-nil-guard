# Preprocessor Macro Cache Design

## Problem Statement

The current preprocessor macro dictionary integration fixes correctness for giant
`id.lua`-style files, but it does not yet scale well for repeated use.

In the customer's real workflow:

- `id.lua` can exceed one million lines
- it is consulted on nearly every review run
- users often run `report-file` repeatedly against small business files
- the macro dictionary itself changes infrequently compared with ordinary source

The current implementation still rebuilds macro facts during each
`bootstrap_repository()`:

- read the entire preprocessor file(s)
- parse every supported assignment line
- rebuild every `MacroFact`
- resolve aliases again
- rebuild the full in-memory `MacroIndex`

For giant macro dictionaries, this leads to:

- long startup time on every run
- unnecessary CPU churn
- large transient and resident memory use
- a poor operator experience even when reviewing a tiny target file

## Core Insight

`id.lua`-style files should not only be treated as **preprocessor inputs**.
They should also be treated as **compilation artifacts**.

That means:

- parse them once when needed
- persist the resolved facts
- reuse the compiled result across later review runs
- only rebuild when the source actually changes

The scanner should continue to review original source files, but it should stop
re-parsing giant macro dictionaries on every run.

## Goals

- Make giant macro dictionaries fast to reuse across repeated runs
- Preserve correctness and deterministic behavior
- Keep original-source review unchanged
- Avoid full in-memory rebuilds for very large macro dictionaries
- Provide explicit operator tooling for cache lifecycle

## Non-Goals

- Do not introduce heuristic or probabilistic macro parsing
- Do not perform textual macro expansion of business source
- Do not execute macro dictionary files
- Do not infer unsupported macro syntax by guesswork
- Do not optimize ordinary business-file AST paths in this design

## Proposed Architecture

Introduce a new layer:

**Compiled Macro Cache**

This layer sits between preprocessor file discovery and runtime static analysis.

### 1. Source of Truth

The source of truth remains:

- configured `preprocessor_files`
- default `id.lua` / `*_id.lua` file-role detection
- the bounded line-oriented macro parser already in the project

The cache does not replace source truth.
It is a compiled artifact derived from that source truth.

### 2. Cache Artifact

The cache stores resolved macro facts in a persistent sidecar database.

Recommended storage:

- SQLite

Reasons:

- built into Python
- deterministic
- supports indexed key lookup
- avoids loading all facts into memory
- easy to invalidate and inspect
- suitable for very large key-value datasets

### 3. Runtime Query Model

At runtime:

- static analysis asks for a symbol/path
- the macro cache returns the resolved fact for that key
- only the requested key is loaded
- hot keys may be memoized in a small in-memory lookup cache

The runtime path should no longer require:

- reparsing the entire macro file
- reconstructing the entire `MacroIndex` for every command

### 4. Cache Validity

The cache must be invalidated when its inputs change.

At minimum, cache validity should depend on:

- preprocessor file path
- file size
- file `mtime_ns`
- parser schema version
- preprocessor config signature

Optional stronger validation:

- file content hash (`sha256`)

### 5. Cache Lifecycle

Two usage modes should exist:

#### Automatic

During `bootstrap_repository()`:

- if a valid cache exists, use it
- if no valid cache exists, build it
- then continue review

This is the default user path.

#### Explicit

Provide operator commands to manage cache intentionally:

- `macro-build-cache`
- `macro-cache-status`
- future optional `macro-clear-cache`

This supports large-repository prewarming and CI workflows.

## Data Model

The current `MacroIndex` is an in-memory tuple of `MacroFact` objects.
That should evolve into two layers:

### Runtime Layer

Keep a lightweight runtime facade, conceptually:

- `MacroStore`
- `lookup(key) -> MacroFact | None`
- optional small memoization map for recent keys

This allows the rest of static analysis to stay mostly unchanged.

### Persistent Layer

Persist one row per resolved macro fact, with fields such as:

- `key`
- `kind`
- `value`
- `provably_non_nil`
- `resolved_kind`
- `resolved_value`
- `file`
- `line`

And a metadata table for:

- source file path
- source file size
- source file mtime
- source file hash (optional)
- parser version
- config signature
- last build timestamp

## Lookup Semantics

The cache should preserve the same semantic contract already established by
`MacroIndex`.

For the caller, lookup should still answer:

- is this symbol/path known?
- is it provably non-nil?
- what kind of value is it?
- where did this fact come from?

That means all existing macro-fact consumption sites can remain conceptually
stable:

- `string.*`
- `concat.*`
- `pairs/ipairs`
- `#`
- comparison
- arithmetic
- `member_access.receiver`

Only the data source changes, not the user-visible semantics.

## Why This Is Better Than Just an In-Memory Dict

An in-memory `dict[str, MacroFact]` is still worth adding as a local
optimization, but by itself it is not enough.

It improves:

- lookup complexity

It does not solve:

- repeated full parsing on every run
- repeated full object reconstruction
- repeated peak memory cost across commands

The compiled cache solves all three.

The best implementation is therefore:

1. persistent compiled cache
2. lightweight runtime store
3. small hot-key memoization

## Recommended CLI

### `macro-build-cache`

Purpose:

- explicitly build or refresh compiled macro cache for one repository

Behavior:

- discover effective preprocessor files
- parse them
- resolve aliases
- write cache
- report counts and invalid lines

### `macro-cache-status`

Purpose:

- show whether a valid cache exists
- show which files are covered
- show whether a rebuild is needed

Suggested output:

- cache path
- cache version
- number of preprocessor files
- number of resolved facts
- number of unresolved lines
- stale / fresh per file

### Optional Future: `macro-clear-cache`

Purpose:

- remove cache explicitly when operators want a clean rebuild

This is useful but not required for the first version.

## Recommended Rollout Strategy

### Stage C1: Fix the Current Complexity Trap

Before or alongside persistence:

- replace linear `lookup_macro_fact()` scans with constant-time lookup

This yields immediate improvement and reduces pressure even before persistence
is complete.

### Stage C2: Add Persistent Compiled Cache

Introduce SQLite sidecar cache and explicit build command.

### Stage C3: Integrate Runtime Automatic Reuse

Make `bootstrap_repository()` prefer valid cache automatically.

### Stage C4: Add Operator Visibility

Expose cache health and freshness in CLI tooling.

## Guardrails

1. Do not let cache logic silently alter review semantics.
2. Do not fall back to lossy or guessed macro parsing.
3. If cache is invalid or unreadable, rebuild deterministically or fail with a
   clear diagnostic.
4. Keep operator-visible provenance (`file`, `line`) intact.
5. Do not let cache become another hidden source of environment drift.

## Acceptance Standard

This design is successful when:

- reviewing a small business file in a repository with a giant `id.lua` no
  longer reparses the giant file every run
- repeated runs are dramatically faster
- macro-backed false positives remain suppressed
- macro cache invalidation is predictable and auditable
- operators can inspect and prebuild cache intentionally

## Strategic Value

This is not merely a performance optimization.

It changes the macro dictionary path from:

- repeated runtime parsing

into:

- precompiled semantic infrastructure

That is the correct long-term model for giant enterprise macro dictionaries.
