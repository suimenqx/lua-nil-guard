from __future__ import annotations

from pathlib import Path
import shutil

from lua_nil_guard.service import (
    benchmark_repository_review,
    bootstrap_repository,
    review_repository,
)


def test_ast_stress_suite_static_scan_moves_all_cases_to_ast_lite_unknown(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "ast_stress_suite"
    runtime_root = tmp_path / "ast_stress_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    assessments = review_repository(snapshot)
    by_name = {
        Path(assessment.candidate.file).name: assessment
        for assessment in assessments
    }

    assert len(assessments) == 4
    assert by_name["provable_safe_shadowed_local_do.lua"].candidate.static_state == "unknown_static"
    assert by_name["provable_safe_deep_nested_if.lua"].candidate.static_state == "unknown_static"
    assert by_name["provable_safe_repeat_until.lua"].candidate.static_state == "unknown_static"
    assert by_name["provable_safe_loop_break.lua"].candidate.static_state == "unknown_static"
    assert all(assessment.static_analysis.analysis_mode == "ast_lite" for assessment in assessments)
    assert all(assessment.static_analysis.proofs == () for assessment in assessments)
    assert all(assessment.static_analysis.risk_signals == () for assessment in assessments)


def test_ast_stress_suite_benchmark_exposes_ast_migration_counts(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1] / "examples" / "mvp_cases" / "ast_stress_suite"
    runtime_root = tmp_path / "ast_stress_suite"
    shutil.copytree(project_root, runtime_root)
    snapshot = bootstrap_repository(runtime_root)

    summary = benchmark_repository_review(snapshot)

    assert summary.total_cases == 4
    assert summary.exact_matches == 0
    assert summary.ast_lite_cases == 4
    assert summary.ast_primary_cases == 0
    assert summary.ast_fallback_to_legacy_cases == 0
    assert summary.legacy_only_cases == 0
