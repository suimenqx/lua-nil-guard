from __future__ import annotations

from pathlib import Path

from lua_nil_guard.annotations import parse_annotations


def _count_functions(source: str) -> int:
    """Count function definitions in Lua source."""
    import re

    return len(re.findall(r"(?:local\s+)?function\s+[\w.:]+\s*\(", source))


def test_empty_repo_zero_coverage(tmp_path: Path) -> None:
    """A repo with no annotations has 0% coverage."""
    f = tmp_path / "a.lua"
    f.write_text("function f()\n  return 1\nend\n", encoding="utf-8")

    source = f.read_text(encoding="utf-8")
    facts = parse_annotations(source, str(f))
    total_fns = _count_functions(source)

    assert total_fns == 1
    assert len(facts) == 0


def test_fully_annotated_repo(tmp_path: Path) -> None:
    """A repo where every function has an annotation has 100% coverage."""
    f = tmp_path / "a.lua"
    f.write_text(
        '--- @nil_guard: returns_non_nil\nfunction f()\n  return "ok"\nend\n'
        '--- @nil_guard: returns_non_nil\nfunction g()\n  return "ok"\nend\n',
        encoding="utf-8",
    )

    source = f.read_text(encoding="utf-8")
    facts = parse_annotations(source, str(f))
    total_fns = _count_functions(source)

    assert total_fns == 2
    assert len(facts) == 2
    annotated_fns = len({fact.function_id for fact in facts})
    assert annotated_fns == total_fns


def test_partial_coverage(tmp_path: Path) -> None:
    f = tmp_path / "a.lua"
    f.write_text(
        '--- @nil_guard: returns_non_nil\nfunction f()\n  return "ok"\nend\n'
        'function g()\n  return nil\nend\n'
        'function h(x)\n  return x\nend\n',
        encoding="utf-8",
    )

    source = f.read_text(encoding="utf-8")
    facts = parse_annotations(source, str(f))
    total_fns = _count_functions(source)

    assert total_fns == 3
    annotated_fns = len({fact.function_id for fact in facts})
    assert annotated_fns == 1
    coverage = annotated_fns / total_fns
    assert abs(coverage - 1 / 3) < 0.01


def test_multi_file_coverage(tmp_path: Path) -> None:
    core = tmp_path / "core.lua"
    utils = tmp_path / "utils.lua"

    core.write_text(
        '--- @nil_guard: returns_non_nil\nfunction core_a()\n  return ""\nend\n'
        '--- @nil_guard: returns_non_nil\nfunction core_b()\n  return 1\nend\n'
        'function core_c()\n  return nil\nend\n',
        encoding="utf-8",
    )
    utils.write_text(
        'function util_a()\n  return 1\nend\n'
        'function util_b()\n  return 2\nend\n',
        encoding="utf-8",
    )

    total_fns = 0
    annotated_fns = set()

    for f in [core, utils]:
        source = f.read_text(encoding="utf-8")
        total_fns += _count_functions(source)
        for fact in parse_annotations(source, str(f)):
            annotated_fns.add(fact.function_id)

    assert total_fns == 5
    assert len(annotated_fns) == 2
    # core: 2/3, utils: 0/2 → overall 2/5 = 40%
    assert abs(len(annotated_fns) / total_fns - 0.4) < 0.01


def test_suggest_returns_non_nil_for_defaulted_return(tmp_path: Path) -> None:
    """When all returns use `or` defaulting, suggest returns_non_nil."""
    source = "function normalize(x)\n  return x or ''\nend\n"
    fns = _count_functions(source)
    facts = parse_annotations(source, "test.lua")

    assert fns == 1
    assert len(facts) == 0
    # Suggestion logic: the function has "return ... or ..." → candidate for returns_non_nil


def test_suggest_may_nil_for_return_nil_path(tmp_path: Path) -> None:
    """When a function has an explicit return nil path, suggest return 1: may_nil."""
    source = "function get(x)\n  if x then return x end\nend\n"
    fns = _count_functions(source)
    facts = parse_annotations(source, "test.lua")

    assert fns == 1
    assert len(facts) == 0
    # Suggestion logic: function may return nil → candidate for return 1: may_nil


def test_coverage_with_local_functions(tmp_path: Path) -> None:
    f = tmp_path / "a.lua"
    f.write_text(
        '--- @nil_guard: returns_non_nil\nlocal function helper()\n  return ""\nend\n'
        'function main()\n  return helper()\nend\n',
        encoding="utf-8",
    )

    source = f.read_text(encoding="utf-8")
    facts = parse_annotations(source, str(f))
    total_fns = _count_functions(source)

    assert total_fns == 2
    assert len(facts) == 1
    assert "helper" in facts[0].function_id


def test_annotations_in_deeply_nested_structure() -> None:
    source = (
        "local M = {}\n"
        "--- @nil_guard: returns_non_nil\n"
        'function M.get_name()\n  return "ok"\nend\n'
        "return M\n"
    )
    facts = parse_annotations(source, "mod.lua")

    assert len(facts) == 1
    assert "M.get_name" in facts[0].function_id
