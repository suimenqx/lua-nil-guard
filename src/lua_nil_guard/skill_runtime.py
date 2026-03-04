from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

ADJUDICATOR_SKILL_CONTRACT = "lua-nil-adjudicator/v1"
BUNDLED_ADJUDICATOR_SKILL_NAME = "lua_nil_adjudicator.SKILL.md"


class SkillRuntimeError(ValueError):
    """Raised when a configured adjudication skill is invalid or incompatible."""


@dataclass(frozen=True)
class SkillDefinition:
    """Parsed representation of a local skill file."""

    path: Path
    name: str
    description: str
    frontmatter: dict[str, str]
    body: str
    sections: dict[str, tuple[str, ...]]


def default_adjudicator_skill_path() -> Path:
    """Return the packaged default adjudicator skill path."""

    return Path(__file__).with_name(BUNDLED_ADJUDICATOR_SKILL_NAME)


def load_skill_definition(path: str | Path) -> SkillDefinition:
    """Parse a skill file into frontmatter and section content."""

    return _load_skill_definition_cached(str(Path(path).resolve()))


def load_adjudicator_skill(path: str | Path | None = None) -> SkillDefinition:
    """Load the default adjudicator skill, or a provided override path."""

    if path is None:
        return _load_bundled_adjudicator_skill()
    return load_skill_definition(path)


def fallback_adjudicator_skill_header() -> str:
    """Return the built-in adjudicator header used when fallback is allowed."""

    return "\n".join(
        [
            "Adjudication policy: lua-nil-adjudicator",
            f"Policy contract: {ADJUDICATOR_SKILL_CONTRACT}",
            "Policy purpose: Strictly adjudicate whether a possibly nil value can reach a nil-sensitive Lua sink with explicit path evidence, strong false-positive control, and machine-readable verdicts.",
            "",
            "Goal:",
            "Produce a precise verdict with minimal false positives.",
            "Judge only this question:",
            "- Can `nil` reach the declared `nil-sensitive` sink on a real path supported by the provided code?",
            "",
            "Required review order:",
            "1. Identify the sink and the exact value expression under review.",
            "2. Look for explicit safety evidence first.",
            "3. If safety is not proven, trace the value origin and path to the sink.",
            "4. Distinguish facts from inference.",
            "5. Return `uncertain` when evidence is incomplete.",
            "",
            "Canonical principles:",
            "- Unknown is not risk.",
            "- Absence of proof is not proof of bug.",
            "",
            "Hard rules:",
            "- Use only the provided code and declared facts.",
            "- Do not assume undocumented business guarantees.",
            "- Do not report risk without a concrete path explanation.",
            "- Do not report safety without explicit supporting evidence.",
            "- Return `uncertain` when evidence is incomplete.",
            "- Treat runtime observations as supporting evidence, not absolute proof, unless the failing path is directly observed.",
            "",
            "Evidence checklist:",
            "Check for these before calling a case risky:",
            "- variable origin",
            "- assignments and reassignments",
            "- nearby guards such as `if x then`",
            "- `assert(x)` style assertions",
            "- defaulting patterns such as `x = x or \"\"`",
            "- wrapper or normalizer functions",
            "- function summaries and repository knowledge facts",
            "",
            "Output contract:",
            "Return a machine-readable object with:",
            "- `status`: `safe`, `risky`, or `uncertain`",
            "- `confidence`: `low`, `medium`, or `high`",
            "- `risk_path`: only explicit, code-supported path steps",
            "- `safety_evidence`: only explicit guards or contracts",
            "- `missing_evidence`: what is still needed if unresolved",
            "- `recommended_next_action`: one of `suppress`, `expand_context`, `verify_runtime`, `report`, `autofix`",
            "- `suggested_fix`: only when a high-confidence, low-risk fix is clear",
            "",
            "Review bias:",
            "- Prefer silence over speculative warnings.",
            "- A sparse, trusted report is better than a noisy report.",
            "- Default to `uncertain` instead of overstating risk.",
        ]
    )


def compile_adjudicator_skill_header(
    path: str | Path | None = None,
    *,
    strict: bool = True,
) -> str:
    """Compile the adjudicator skill into a stable runtime instruction header."""

    try:
        skill = load_adjudicator_skill(path)
        _ensure_adjudicator_skill_contract(skill)
        required_sections = (
            "Goal",
            "Required Review Order",
            "Canonical Principles",
            "Hard Rules",
            "Evidence Checklist",
            "Output Contract",
            "Review Bias",
        )
        missing = [title for title in required_sections if title not in skill.sections]
        if missing:
            raise SkillRuntimeError(f"Skill is missing required sections: {', '.join(missing)}")

        lines = [
            f"Adjudication policy: {skill.name}",
            f"Policy contract: {ADJUDICATOR_SKILL_CONTRACT}",
            f"Policy purpose: {skill.description}",
        ]
        for title in required_sections:
            lines.append("")
            lines.append(f"{_format_section_label(title)}:")
            lines.extend(skill.sections[title])
        return "\n".join(lines)
    except (OSError, ValueError) as exc:
        if strict:
            if isinstance(exc, SkillRuntimeError):
                raise
            raise SkillRuntimeError(str(exc))
        return fallback_adjudicator_skill_header()


@lru_cache(maxsize=16)
def _load_skill_definition_cached(resolved_path: str) -> SkillDefinition:
    path = Path(resolved_path)
    content = path.read_text(encoding="utf-8")
    return _parse_skill_definition(content, path)


@lru_cache(maxsize=1)
def _load_bundled_adjudicator_skill() -> SkillDefinition:
    resource = resources.files("lua_nil_guard").joinpath(BUNDLED_ADJUDICATOR_SKILL_NAME)
    content = resource.read_text(encoding="utf-8")
    return _parse_skill_definition(content, default_adjudicator_skill_path())


def _parse_skill_definition(content: str, path: Path) -> SkillDefinition:
    frontmatter, body = _split_frontmatter(content, path)
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not name or not description:
        raise ValueError(f"Skill frontmatter is missing name or description: {path}")
    return SkillDefinition(
        path=path,
        name=name,
        description=description,
        frontmatter=frontmatter,
        body=body,
        sections=_parse_sections(body),
    )


def _split_frontmatter(content: str, path: Path) -> tuple[dict[str, str], str]:
    lines = content.splitlines()
    if len(lines) < 3 or lines[0] != "---":
        raise ValueError(f"Skill frontmatter is missing opening delimiter: {path}")
    try:
        closing_index = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError(f"Skill frontmatter is missing closing delimiter: {path}") from exc

    frontmatter: dict[str, str] = {}
    for raw_line in lines[1:closing_index]:
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        frontmatter[key.strip()] = value.strip()

    body = "\n".join(lines[closing_index + 1 :]).strip()
    return frontmatter, body


def _parse_sections(body: str) -> dict[str, tuple[str, ...]]:
    sections: dict[str, list[str]] = {}
    current_title: str | None = None

    for raw_line in body.splitlines():
        line = raw_line.rstrip()
        if line.startswith("## "):
            current_title = line[3:].strip()
            sections.setdefault(current_title, [])
            continue
        if current_title is None:
            continue
        if not line.strip():
            continue
        sections[current_title].append(line)

    return {title: tuple(entries) for title, entries in sections.items()}


def _format_section_label(title: str) -> str:
    return title[:1] + title[1:].lower()


def _ensure_adjudicator_skill_contract(skill: SkillDefinition) -> None:
    declared = skill.frontmatter.get("skill_contract")
    if declared != ADJUDICATOR_SKILL_CONTRACT:
        if declared is None:
            raise SkillRuntimeError(
                f"Skill is missing required skill_contract: {ADJUDICATOR_SKILL_CONTRACT}"
            )
        raise SkillRuntimeError(
            f"Unsupported skill_contract: {declared} (expected {ADJUDICATOR_SKILL_CONTRACT})"
        )
