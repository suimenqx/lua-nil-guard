from __future__ import annotations

from pathlib import Path

from lua_nil_review_agent.service import prepare_evidence_packet, review_source
from lua_nil_review_agent.models import SinkRule


def test_prepare_evidence_packet_uses_static_assessment_context() -> None:
    sink_rules = (
        SinkRule(
            id="string.match.arg1",
            kind="function_arg",
            qualified_name="string.match",
            arg_index=1,
            nil_sensitive=True,
            failure_mode="runtime_error",
            default_severity="high",
            safe_patterns=("x or ''",),
        ),
    )
    source = "\n".join(
        [
            "local username = req.params.username",
            "if username then",
            "  return string.match(username, '^a')",
            "end",
        ]
    )
    assessment = review_source(Path("foo.lua"), source, sink_rules)[0]

    packet = prepare_evidence_packet(
        assessment,
        source,
        related_functions=("normalize_name",),
        function_summaries=("normalize_name always returns string",),
        knowledge_facts=("req.params may be nil",),
    )

    assert packet.case_id == assessment.candidate.case_id
    assert "string.match" in packet.local_context
    assert packet.static_reasoning["state"] == "safe_static"
    assert packet.static_reasoning["analysis_mode"] == assessment.static_analysis.analysis_mode
    assert packet.static_reasoning["unknown_reason"] == (
        assessment.static_analysis.unknown_reason or ""
    )
    assert packet.static_reasoning["origin_analysis_mode"] == (
        assessment.static_analysis.origin_analysis_mode
    )
    assert packet.static_reasoning["origin_unknown_reason"] == (
        assessment.static_analysis.origin_unknown_reason or ""
    )
    assert packet.static_reasoning["observed_guards"] == ("if username then",)
    assert packet.static_reasoning["proof_kinds"] == ("direct_guard",)
    assert packet.static_reasoning["origin_candidates"] == ("req.params.username",)
    assert len(packet.static_proofs) == 1
    assert packet.static_proofs[0].summary == "if username then"
    assert packet.static_proofs[0].subject == "username"
