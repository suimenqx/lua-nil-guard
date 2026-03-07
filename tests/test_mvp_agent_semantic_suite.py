from __future__ import annotations

import json
from pathlib import Path
import shutil

from lua_nil_guard.models import AdjudicationRecord, RoleOpinion, Verdict
from lua_nil_guard.service import (
    bootstrap_repository,
    export_adjudication_tasks,
    refresh_knowledge_base,
    run_repository_review,
)


class StrictEvidenceBackend:
    """Deterministic stand-in for a strict external adjudication agent."""

    def adjudicate(self, packet, sink_rule):  # noqa: ANN001
        observed_guards = _tuple_field(packet.static_reasoning, "observed_guards")
        origins = _tuple_field(packet.static_reasoning, "origin_candidates")
        safety_facts = tuple(
            fact for fact in packet.knowledge_facts if "returns non-nil" in fact.lower()
        )

        if observed_guards or safety_facts:
            safety_evidence = observed_guards or safety_facts
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("safety evidence blocks a clean risk proof",),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="safe",
                    confidence="high" if observed_guards else "medium",
                    risk_path=(),
                    safety_evidence=safety_evidence,
                    missing_evidence=(),
                    recommended_next_action="suppress",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="high" if observed_guards else "medium",
                    risk_path=(),
                    safety_evidence=safety_evidence,
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
            )

        if _locally_proves_nil(origins, packet.local_context):
            risk_path = origins or ("explicit nil flow in local context",)
            return AdjudicationRecord(
                prosecutor=RoleOpinion(
                    role="prosecutor",
                    status="risky",
                    confidence="high",
                    risk_path=risk_path,
                    safety_evidence=(),
                    missing_evidence=(),
                    recommended_next_action="report",
                    suggested_fix=f"local safe_value = {packet.target.expression} or ''",
                ),
                defender=RoleOpinion(
                    role="defender",
                    status="uncertain",
                    confidence="low",
                    risk_path=(),
                    safety_evidence=(),
                    missing_evidence=("no explicit safety proof",),
                    recommended_next_action="expand_context",
                    suggested_fix=None,
                ),
                judge=Verdict(
                    case_id=packet.case_id,
                    status="risky",
                    confidence="high",
                    risk_path=risk_path,
                    safety_evidence=(),
                    counterarguments_considered=("no explicit safety proof",),
                    suggested_fix=f"local safe_value = {packet.target.expression} or ''",
                    needs_human=False,
                ),
            )

        return AdjudicationRecord(
            prosecutor=RoleOpinion(
                role="prosecutor",
                status="uncertain",
                confidence="low",
                risk_path=origins,
                safety_evidence=(),
                missing_evidence=("origin may be nil, but no code-proven nil path exists",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            defender=RoleOpinion(
                role="defender",
                status="uncertain",
                confidence="low",
                risk_path=(),
                safety_evidence=(),
                missing_evidence=("no explicit guard or trusted non-nil contract found",),
                recommended_next_action="expand_context",
                suggested_fix=None,
            ),
            judge=Verdict(
                case_id=packet.case_id,
                status="uncertain",
                confidence="medium",
                risk_path=origins,
                safety_evidence=(),
                counterarguments_considered=("insufficient local proof either way",),
                suggested_fix=None,
                needs_human=True,
            ),
        )


def test_agent_semantic_suite_strict_backend_distinguishes_risky_safe_and_uncertain(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    facts = refresh_knowledge_base(snapshot)
    verdicts = run_repository_review(snapshot, backend=StrictEvidenceBackend())

    statuses = {verdict.case_id: verdict.status for verdict in verdicts}

    fact_subjects = {fact.subject for fact in facts}

    assert fact_subjects == {"normalize_name", "normalize_pair"}
    assert len(verdicts) == 18
    assert any("provable_risky_nil_literal.lua" in case_id and status == "risky" for case_id, status in statuses.items())
    assert any("provable_risky_nil_branch.lua" in case_id and status == "risky" for case_id, status in statuses.items())
    assert any("provable_risky_gsub_nil.lua" in case_id and status == "risky" for case_id, status in statuses.items())
    assert any("provable_risky_ipairs_nil.lua" in case_id and status == "risky" for case_id, status in statuses.items())
    assert any("provable_risky_length_nil.lua" in case_id and status == "risky" for case_id, status in statuses.items())
    assert any("provable_safe_if_guard.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any("provable_safe_assert.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any("provable_safe_default.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any("provable_safe_table_insert_default.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any("provable_safe_pairs_default.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any("provable_safe_length_default.lua" in case_id and status == "safe_verified" for case_id, status in statuses.items())
    assert any(
        "provable_safe_normalized.lua" in case_id and status.startswith("safe")
        for case_id, status in statuses.items()
    )
    assert any(
        "provable_safe_multi_return.lua" in case_id and status.startswith("safe")
        for case_id, status in statuses.items()
    )
    assert any("provable_uncertain_field.lua" in case_id and status == "risky_verified" for case_id, status in statuses.items())
    assert any("provable_uncertain_wrapper.lua" in case_id and status == "risky_verified" for case_id, status in statuses.items())
    assert any("provable_uncertain_table_insert_field.lua" in case_id and status == "risky_verified" for case_id, status in statuses.items())
    assert any("provable_uncertain_pairs_field.lua" in case_id and status == "risky_verified" for case_id, status in statuses.items())
    assert any("provable_uncertain_length_field.lua" in case_id and status == "risky_verified" for case_id, status in statuses.items())


def test_agent_semantic_suite_prompt_export_contains_agent_useful_evidence(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "agent_semantic_suite"
    runtime_root = tmp_path / "agent_semantic_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    refresh_knowledge_base(snapshot)
    tasks = export_adjudication_tasks(snapshot)
    prompt_by_file = {Path(task["file"]).name: task["prompt"] for task in tasks}

    assert "Adjudication policy: lua-nil-adjudicator" in prompt_by_file["provable_risky_nil_branch.lua"]
    assert "req.force_nil and nil or \"admin\"" in prompt_by_file["provable_risky_nil_branch.lua"]
    assert "sink: string.gsub" in prompt_by_file["provable_risky_gsub_nil.lua"]
    assert "sink: ipairs" in prompt_by_file["provable_risky_ipairs_nil.lua"]
    assert "sink: #" in prompt_by_file["provable_risky_length_nil.lua"]
    assert "observed_guards: assert(token)" in prompt_by_file["provable_safe_assert.lua"]
    assert "Knowledge facts:\n(none)" in prompt_by_file["provable_safe_normalized.lua"]
    assert "Related functions:\n(none)" in prompt_by_file["provable_safe_multi_return.lua"]
    assert "Knowledge facts:\n(none)" in prompt_by_file["provable_safe_multi_return.lua"]
    assert "sink: table.insert" in prompt_by_file["provable_safe_table_insert_default.lua"]
    assert "observed_guards: names = names or ..." in prompt_by_file["provable_safe_table_insert_default.lua"]
    assert "sink: pairs" in prompt_by_file["provable_safe_pairs_default.lua"]
    assert "observed_guards: items = items or ..." in prompt_by_file["provable_safe_pairs_default.lua"]
    assert "sink: #" in prompt_by_file["provable_safe_length_default.lua"]
    assert "observed_guards: items = items or ..." in prompt_by_file["provable_safe_length_default.lua"]
    assert "Related functions:\n(none)" in prompt_by_file["provable_uncertain_wrapper.lua"]
    assert "Knowledge facts:\n(none)" in prompt_by_file["provable_uncertain_wrapper.lua"]
    assert "sink: table.insert" in prompt_by_file["provable_uncertain_table_insert_field.lua"]
    assert "sink: pairs" in prompt_by_file["provable_uncertain_pairs_field.lua"]
    assert "sink: #" in prompt_by_file["provable_uncertain_length_field.lua"]


def _tuple_field(values: dict[str, tuple[str, ...] | str], key: str) -> tuple[str, ...]:
    current = values.get(key, ())
    if isinstance(current, tuple):
        return current
    return ()


def _locally_proves_nil(origins: tuple[str, ...], local_context: str) -> bool:
    if any(origin.strip() == "nil" for origin in origins):
        return True
    return " and nil or " in local_context
