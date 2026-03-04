# Plan 4: Compiled Macro Cache for Large Preprocessor Files

## 1. Purpose

This plan turns the design in
[internal/preprocessor-macro-cache-design.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/preprocessor-macro-cache-design.md)
into an implementation roadmap.

The practical customer goal is clear:

- stop reparsing giant `id.lua` macro dictionaries on every run
- keep the existing macro-fact correctness model
- drastically reduce repeat-run latency and memory pressure

This is a targeted scaling plan for preprocessor dictionaries, not a broad
repository-wide caching rewrite.

## 2. Problem Recap

The project already treats `id.lua` and `*_id.lua` as preprocessor inputs.
That solved the correctness and false-positive model, but not repeated-run
performance.

Today, every repository bootstrap still:

- reads every preprocessor file
- parses every supported assignment line
- resolves aliases
- rebuilds a fresh in-memory `MacroIndex`

For customer repositories with million-line macro dictionaries, that means even
`report-file` against a tiny business file can still feel slow.

## 3. Product Principles

All implementation decisions in this plan must satisfy these principles:

1. Preserve original-source review.
2. Preserve bounded, deterministic macro parsing.
3. Improve repeated-run performance without weakening correctness.
4. Make cache behavior explicit, auditable, and reproducible.
5. Prefer a narrow preprocessor-specific cache over a broad speculative cache.

If implementation starts drifting, stop and re-read:

- [internal/preprocessor-macro-dictionary-design.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/preprocessor-macro-dictionary-design.md)
- [internal/preprocessor-macro-cache-design.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/preprocessor-macro-cache-design.md)

## 4. Scope

### In Scope

- replacing linear macro lookup with constant-time runtime lookup
- adding a persistent compiled cache for preprocessor facts
- cache freshness and invalidation checks
- explicit CLI commands for building and inspecting macro cache
- automatic runtime reuse of valid macro cache

### Out of Scope

- full repository AST cache
- generic business-file caching
- aggressive concurrent parsing changes
- changing the bounded macro syntax supported by `plan3`
- arbitrary schema migration for unrelated project data

## 5. Deliverables

By the end of `plan4`, the project should have:

1. O(1) macro lookup for the in-process path.
2. A persistent compiled cache for preprocessor facts.
3. Automatic reuse of valid macro cache during repository bootstrap.
4. Explicit CLI commands to build and inspect cache state.
5. Tests proving repeated-run paths no longer require reparsing to obtain macro
   facts.

## 6. Execution Phases

### Phase C1: Eliminate Linear Macro Lookup

#### Objective

Remove the current `O(n)` scan in `lookup_macro_fact()` before introducing
longer-lived persistence.

#### Required Changes

1. Extend runtime macro storage to keep a keyed lookup structure.
2. Ensure existing callers keep using the same logical API.
3. Preserve provenance fields (`file`, `line`) and resolved value fields.

#### Acceptance Criteria

- Macro fact lookup no longer scans the full fact tuple.
- Existing semantic behavior is unchanged.
- All current macro-based false-positive suppressions still work.

#### Test Coverage

Add or update tests proving:

- lookup by exact key still returns the same fact
- alias-resolved facts remain accessible
- missing keys still fail closed

### Phase C2: Persistent Cache Format

#### Objective

Persist resolved macro facts to a deterministic sidecar cache.

#### Required Changes

1. Introduce a cache file location under the repository, preferably in a hidden
   tool-owned directory.
2. Implement a persistent store for:
   - resolved macro facts
   - unresolved macro lines
   - cache metadata
3. Keep the runtime representation compatible with current static-analysis
   consumers.

#### Acceptance Criteria

- A repository with preprocessor files can build a cache artifact on disk.
- Cache contents preserve:
  - key
  - kind
  - resolved kind/value
  - provably non-nil flag
  - provenance

#### Test Coverage

Add tests for:

- cache file creation
- cache readback preserving fact content
- unresolved macro lines preserved for audit paths

### Phase C3: Cache Freshness and Invalidation

#### Objective

Ensure stale cache is never silently reused.

#### Required Changes

1. Define cache validity inputs:
   - preprocessor file path
   - file size
   - file `mtime_ns`
   - parser/cache schema version
   - config signature
2. Check validity before reuse.
3. Rebuild cache automatically when validity fails.

#### Acceptance Criteria

- Unchanged files reuse cache.
- Changing a preprocessor file invalidates cache.
- Changing `preprocessor_files` configuration invalidates cache.
- Corrupt or unreadable cache never silently degrades into wrong facts.

#### Test Coverage

Add tests for:

- unchanged file -> cache reused
- modified file -> cache rebuilt
- modified config -> cache rebuilt
- corrupt cache -> rebuild or fail with clear error

### Phase C4: CLI Cache Controls

#### Objective

Give operators explicit control over cache creation and visibility.

#### Required Changes

1. Add:
   - `macro-build-cache`
   - `macro-build-cache-json`
2. Add:
   - `macro-cache-status`
   - `macro-cache-status-json`
3. Make output operator-focused and concise.

#### Acceptance Criteria

- Operators can prebuild cache without running a full review.
- Operators can see whether cache is fresh or stale.
- JSON variants are suitable for automation.

#### Test Coverage

Add tests for:

- command registration in help
- successful cache build output
- status output on fresh cache
- status output on stale cache

### Phase C5: Automatic Runtime Reuse

#### Objective

Make ordinary review flows benefit from cache without extra operator steps.

#### Required Changes

1. Update `bootstrap_repository()` so it:
   - prefers valid cache
   - builds cache if missing/stale
   - exposes a runtime macro store backed by cached facts
2. Ensure this path works for:
   - `report`
   - `report-file`
   - `macro-audit`
   - proposal flows that depend on repository bootstrap

#### Acceptance Criteria

- Repeated `report-file` runs on the same repository do not reparse unchanged
  giant preprocessor files.
- Macro-based proof behavior remains unchanged.
- Customer macro-backed access patterns still resolve correctly.

#### Test Coverage

Add tests proving:

- second bootstrap reuses cache
- macro facts still suppress `string.*`, arithmetic, and `member_access`
- `id.lua` default handling still participates in cache path

### Phase C6: Observability and Guardrails

#### Objective

Make cache behavior understandable enough for enterprise operators.

#### Required Changes

1. Surface cache origin and freshness in operator tools.
2. Optionally extend `doctor` to show macro cache status.
3. Keep documentation explicit about:
   - automatic reuse
   - when rebuild happens
   - how to manually prebuild cache

#### Acceptance Criteria

- Operators can distinguish:
  - cache hit
  - cache rebuild
  - cache unavailable
- Documentation gives a clear recommended workflow for giant macro files.

#### Test Coverage

Add tests for:

- status rendering
- `doctor` integration if implemented
- documentation examples remain accurate

## 7. Execution Order

The phases above must be completed in this order:

1. `C1` first, because it improves both the current in-memory path and the
   future cache-backed path.
2. `C2` and `C3` next, because persistence without validity checks is unsafe.
3. `C4` before automatic runtime reuse, so operators can inspect and prebuild
   cache intentionally.
4. `C5` after the cache is trustworthy.
5. `C6` as the final polish and supportability step.

## 8. Guardrails

1. Do not change macro parsing semantics and caching semantics in the same step
   without tests proving both.
2. Do not let cache silently suppress parser failures.
3. Do not let stale cache survive schema changes.
4. Do not introduce broad repository-wide caching under this plan.
5. Do not sacrifice provenance for performance.

## 9. Success Metrics

`plan4` should be considered successful when:

1. Re-running `report-file` on a repository with a giant `id.lua` clearly avoids
   reparsing unchanged macro files.
2. Macro-backed false-positive suppressions still hold.
3. Cache freshness behavior is predictable and test-covered.
4. Operators have explicit commands to build and inspect cache.

## 10. Acceptance Fixture

The implementation must continue to support a realistic customer pattern:

Preprocessor file:

```lua
AAA = 1
_fid_a = {}
_fid_a.name = 1
_fid_a.id = 2
```

Business file:

```lua
function show()
    print(_fid_a.name)
end
```

Required result:

- `id.lua` is treated as a preprocessor file
- it contributes macro facts
- `_fid_a.name` does not trigger a nil-receiver false positive
- repeated scans do not require reparsing the giant macro file when unchanged

## 11. After Plan 4

Once this plan is complete, the next priority should be:

- measuring real customer repeat-run latency
- then deciding whether the broader repository should receive similar compiled
  caches

Do not prematurely widen the caching scope before this preprocessor-specific
cache proves its value.
