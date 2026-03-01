from __future__ import annotations

from pathlib import Path

import pytest

from lua_nil_review_agent.models import CandidateCase, SinkRule
from lua_nil_review_agent.pipeline import build_evidence_packet
from lua_nil_review_agent.prompting import build_adjudication_prompt


ROOT = Path(__file__).resolve().parents[1]


def test_build_adjudication_prompt_includes_evidence_and_hard_rules() -> None:
    candidate = CandidateCase(
        case_id="case_007",
        file="foo/bar.lua",
        line=42,
        column=3,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="username",
        symbol="username",
        function_scope="parse_user",
        static_state="unknown_static",
    )
    packet = build_evidence_packet(
        candidate=candidate,
        local_context="local username = req.params.username",
        related_functions=("normalize_name",),
        function_summaries=("normalize_name always returns string",),
        knowledge_facts=("req.params may be nil",),
        origin_candidates=("req.params.username",),
        observed_guards=("if username then",),
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=("x or ''", "assert(x)"),
    )

    prompt = build_adjudication_prompt(packet=packet, sink_rule=rule)

    assert "case_007" in prompt
    assert "foo/bar.lua" in prompt
    assert "string.match" in prompt
    assert "req.params may be nil" in prompt
    assert "Skill: lua-nil-adjudicator" in prompt
    assert "Required review order:" in prompt
    assert "Unknown is not risk." in prompt
    assert "Absence of proof is not proof of bug." in prompt


def test_build_adjudication_prompt_uses_compiled_skill_header(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = CandidateCase(
        case_id="case_skill_header",
        file="foo.lua",
        line=1,
        column=1,
        sink_rule_id="string.match.arg1",
        sink_name="string.match",
        arg_index=1,
        expression="name",
        symbol="name",
        function_scope="demo",
        static_state="unknown_static",
    )
    packet = build_evidence_packet(
        candidate=candidate,
        local_context="return string.match(name, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        origin_candidates=(),
        observed_guards=(),
    )
    rule = SinkRule(
        id="string.match.arg1",
        kind="function_arg",
        qualified_name="string.match",
        arg_index=1,
        nil_sensitive=True,
        failure_mode="runtime_error",
        default_severity="high",
        safe_patterns=(),
    )

    monkeypatch.setattr(
        "lua_nil_review_agent.prompting.compile_adjudicator_skill_header",
        lambda skill_path=None, strict=True: "SKILL HEADER FOR TESTS",
    )

    prompt = build_adjudication_prompt(packet=packet, sink_rule=rule)

    assert prompt.startswith("SKILL HEADER FOR TESTS")


def test_skill_file_exists_with_required_frontmatter() -> None:
    skill_path = ROOT / "skills" / "lua-nil-adjudicator" / "SKILL.md"

    assert skill_path.exists()
    content = skill_path.read_text(encoding="utf-8")
    assert content.startswith("---\nname: lua-nil-adjudicator\n")
    assert "Return `uncertain` when evidence is incomplete." in content
    assert "Unknown is not risk." in content
    assert "Absence of proof is not proof of bug." in content
