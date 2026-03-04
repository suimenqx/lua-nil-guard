from __future__ import annotations

from pathlib import Path

from lua_nil_guard.models import PreprocessorConfig
from lua_nil_guard.preprocessor import (
    build_macro_audit,
    build_macro_cache,
    build_macro_index,
    ensure_macro_index,
    inspect_macro_cache,
    lookup_macro_fact,
    macro_cache_path,
    parse_macro_file,
    resolve_macro_facts,
    split_preprocessor_files,
)


def test_parse_macro_file_reads_literals_aliases_and_unresolved_lines(tmp_path: Path) -> None:
    file_path = tmp_path / "macros.lua"
    source = "\n".join(
        [
            "-- comment",
            "USER_NAME = \"\"",
            "MAX_LEVEL = 100",
            "DEFAULTS = {}",
            "NAME_ALIAS = USER_NAME",
            "Defaults.Name = \"guest\"",
            "BROKEN = some_call()",
        ]
    )

    facts, unresolved = parse_macro_file(file_path, source, root=tmp_path)

    assert tuple(fact.key for fact in facts) == (
        "USER_NAME",
        "MAX_LEVEL",
        "DEFAULTS",
        "NAME_ALIAS",
        "Defaults.Name",
    )
    assert facts[0].kind == "string_literal"
    assert facts[1].kind == "number_literal"
    assert facts[2].kind == "empty_table"
    assert facts[3].kind == "alias"
    assert facts[3].alias_target == "USER_NAME"
    assert facts[4].key == "Defaults.Name"
    assert len(unresolved) == 1
    assert unresolved[0].reason == "unsupported_value_syntax"


def test_resolve_macro_facts_handles_direct_aliases_and_cycles() -> None:
    facts, _unresolved = parse_macro_file(
        "macros.lua",
        "\n".join(
            [
                "BASE = 1",
                "ALIAS = BASE",
                "A = B",
                "B = A",
            ]
        ),
    )

    resolved = {fact.key: fact for fact in resolve_macro_facts(facts)}

    assert resolved["ALIAS"].provably_non_nil is True
    assert resolved["ALIAS"].resolved_kind == "number_literal"
    assert resolved["ALIAS"].resolved_value == "1"
    assert resolved["A"].provably_non_nil is False
    assert resolved["A"].resolved_kind is None
    assert resolved["B"].provably_non_nil is False


def test_split_preprocessor_files_respects_explicit_and_glob_rules(tmp_path: Path) -> None:
    src = tmp_path / "src"
    legacy = tmp_path / "legacy"
    src.mkdir()
    legacy.mkdir()
    business = src / "demo.lua"
    macro = src / "macros.lua"
    globbed = legacy / "defaults.lua"
    for file_path in (business, macro, globbed):
        file_path.write_text("return nil\n", encoding="utf-8")

    review_files, preprocessor_files = split_preprocessor_files(
        tmp_path,
        (business, macro, globbed),
        PreprocessorConfig(
            preprocessor_files=("src/macros.lua",),
            preprocessor_globs=("legacy/*.lua",),
        ),
    )

    assert review_files == (business,)
    assert preprocessor_files == (macro, globbed)


def test_build_macro_index_and_audit_use_source_loader(tmp_path: Path) -> None:
    macro = tmp_path / "macros.lua"
    macro.write_text("GREETING = \"hi\"\nTABLE = {}\n", encoding="utf-8")

    audit = build_macro_audit(
        tmp_path,
        (macro,),
        source_loader=lambda path: path.read_text(encoding="utf-8"),
    )
    index = build_macro_index(
        tmp_path,
        (macro,),
        source_loader=lambda path: path.read_text(encoding="utf-8"),
    )

    assert audit.files == (str(macro),)
    assert len(audit.facts) == 2
    assert len(index.facts) == 2
    assert any(fact.key == "GREETING" and fact.provably_non_nil for fact in index.facts)


def test_build_macro_cache_and_ensure_macro_index_reuse_fresh_cache(tmp_path: Path) -> None:
    macro = tmp_path / "macros.lua"
    macro.write_text("GREETING = \"hi\"\nTABLE = {}\n", encoding="utf-8")

    built_index, build_status = build_macro_cache(
        tmp_path,
        (macro,),
        source_loader=lambda path: path.read_text(encoding="utf-8"),
    )
    reused_index, reused_status = ensure_macro_index(
        tmp_path,
        (macro,),
        source_loader=lambda path: path.read_text(encoding="utf-8"),
    )

    assert build_status.state == "rebuilt"
    assert build_status.fact_count == 2
    assert built_index.fact_by_key["GREETING"].resolved_value == "hi"
    assert macro_cache_path(tmp_path).is_file()
    assert reused_status.state == "fresh"
    assert reused_index.cache_connection is not None
    assert reused_index.facts == ()
    assert reused_index.unresolved_lines == ()
    reused_fact = lookup_macro_fact(reused_index, "GREETING")
    assert reused_fact is not None
    assert reused_fact.resolved_value == "hi"


def test_inspect_macro_cache_detects_stale_source_change(tmp_path: Path) -> None:
    macro = tmp_path / "macros.lua"
    macro.write_text("GREETING = \"hi\"\n", encoding="utf-8")
    build_macro_cache(
        tmp_path,
        (macro,),
        source_loader=lambda path: path.read_text(encoding="utf-8"),
    )
    macro.write_text("GREETING = \"hello\"\n", encoding="utf-8")

    status = inspect_macro_cache(tmp_path, (macro,))

    assert status.state == "stale"
    assert "preprocessor source changed" in status.reason
