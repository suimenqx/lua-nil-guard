from __future__ import annotations

from lua_nil_review_agent.models import EvidencePacket, EvidenceTarget, Verdict
from lua_nil_review_agent.verification import verify_verdict


def test_verify_verdict_upgrades_clear_risk_to_risky_verified() -> None:
    verdict = Verdict(
        case_id="case_risky",
        status="risky",
        confidence="medium",
        risk_path=("username <- req.params.username", "no guard before string.match"),
        safety_evidence=(),
        counterarguments_considered=(),
        suggested_fix="local safe_value = username or ''",
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_risky",
        target=EvidenceTarget(
            file="demo.lua",
            line=2,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="local username = req.params.username\nreturn string.match(username, '^a')",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "unknown_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": (),
        },
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "risky_verified"
    assert result.confidence == "high"


def test_verify_verdict_upgrades_safe_to_safe_verified_when_guard_exists() -> None:
    verdict = Verdict(
        case_id="case_safe",
        status="safe",
        confidence="medium",
        risk_path=(),
        safety_evidence=("if username then",),
        counterarguments_considered=(),
        suggested_fix=None,
        needs_human=False,
    )
    packet = EvidencePacket(
        case_id="case_safe",
        target=EvidenceTarget(
            file="demo.lua",
            line=3,
            column=1,
            sink="string.match",
            arg_index=1,
            expression="username",
        ),
        local_context="if username then\n  return string.match(username, '^a')\nend",
        related_functions=(),
        function_summaries=(),
        knowledge_facts=(),
        static_reasoning={
            "state": "safe_static",
            "origin_candidates": ("req.params.username",),
            "observed_guards": ("if username then",),
        },
    )

    result = verify_verdict(verdict, packet)

    assert result.status == "safe_verified"
    assert result.confidence == "high"
