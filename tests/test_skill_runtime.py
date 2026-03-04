from __future__ import annotations

from pathlib import Path

import pytest

from lua_nil_guard.skill_runtime import (
    ADJUDICATOR_SKILL_CONTRACT,
    SkillRuntimeError,
    compile_adjudicator_skill_header,
    fallback_adjudicator_skill_header,
    load_skill_definition,
)


def test_load_skill_definition_parses_frontmatter_and_sections(tmp_path: Path) -> None:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(
        "\n".join(
            [
                "---",
                "name: demo-skill",
                "description: Demo skill for tests.",
                f"skill_contract: {ADJUDICATOR_SKILL_CONTRACT}",
                "---",
                "",
                "# Demo Skill",
                "",
                "## Goal",
                "",
                "Stay strict.",
                "",
                "## Hard Rules",
                "",
                "- First rule",
                "- Second rule",
            ]
        ),
        encoding="utf-8",
    )

    skill = load_skill_definition(skill_path)

    assert skill.name == "demo-skill"
    assert skill.description == "Demo skill for tests."
    assert skill.frontmatter["skill_contract"] == ADJUDICATOR_SKILL_CONTRACT
    assert skill.sections["Goal"] == ("Stay strict.",)
    assert skill.sections["Hard Rules"] == ("- First rule", "- Second rule")


def test_compile_adjudicator_skill_header_contains_canonical_constraints() -> None:
    header = compile_adjudicator_skill_header()

    assert "Adjudication policy: lua-nil-adjudicator" in header
    assert f"Policy contract: {ADJUDICATOR_SKILL_CONTRACT}" in header
    assert "Unknown is not risk." in header
    assert "Absence of proof is not proof of bug." in header
    assert "Do not assume undocumented business guarantees." in header
    assert "Return `uncertain` when evidence is incomplete." in header


def test_compile_adjudicator_skill_header_can_fallback_when_skill_is_invalid(tmp_path: Path) -> None:
    invalid_skill = tmp_path / "invalid-skill.md"
    invalid_skill.write_text(
        "\n".join(
            [
                "---",
                "name: broken-skill",
                "description: Broken skill.",
                "---",
                "",
                "## Goal",
                "- Incomplete on purpose.",
            ]
        ),
        encoding="utf-8",
    )

    header = compile_adjudicator_skill_header(invalid_skill, strict=False)

    assert header == fallback_adjudicator_skill_header()
    assert "Adjudication policy: lua-nil-adjudicator" in header


def test_compile_adjudicator_skill_header_rejects_incompatible_contract(tmp_path: Path) -> None:
    invalid_skill = tmp_path / "wrong-contract.md"
    invalid_skill.write_text(
        "\n".join(
            [
                "---",
                "name: wrong-contract",
                "description: Wrong contract.",
                "skill_contract: lua-nil-adjudicator/v2",
                "---",
                "",
                "## Goal",
                "- Incompatible on purpose.",
                "",
                "## Required Review Order",
                "1. Read the sink.",
                "",
                "## Canonical Principles",
                "- Unknown is not risk.",
                "- Absence of proof is not proof of bug.",
                "",
                "## Hard Rules",
                "- Return `uncertain` when evidence is incomplete.",
                "- Do not assume undocumented business guarantees.",
                "",
                "## Evidence Checklist",
                "- variable origin",
                "",
                "## Output Contract",
                "- `status`: `safe`, `risky`, or `uncertain`",
                "",
                "## Review Bias",
                "- Prefer silence over speculative warnings.",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SkillRuntimeError, match="Unsupported skill_contract"):
        compile_adjudicator_skill_header(invalid_skill)
