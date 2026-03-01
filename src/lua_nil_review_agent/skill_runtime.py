from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class SkillDefinition:
    """Parsed representation of a local skill file."""

    path: Path
    name: str
    description: str
    body: str
    sections: dict[str, tuple[str, ...]]


def default_adjudicator_skill_path() -> Path:
    """Return the repository-local adjudicator skill path."""

    return Path(__file__).resolve().parents[2] / "skills" / "lua-nil-adjudicator" / "SKILL.md"


def load_skill_definition(path: str | Path) -> SkillDefinition:
    """Parse a skill file into frontmatter and section content."""

    return _load_skill_definition_cached(str(Path(path).resolve()))


def load_adjudicator_skill(path: str | Path | None = None) -> SkillDefinition:
    """Load the default adjudicator skill, or a provided override path."""

    return load_skill_definition(path or default_adjudicator_skill_path())


def compile_adjudicator_skill_header(path: str | Path | None = None) -> str:
    """Compile the adjudicator skill into a stable runtime instruction header."""

    skill = load_adjudicator_skill(path)
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
        raise ValueError(f"Skill is missing required sections: {', '.join(missing)}")

    lines = [
        f"Skill: {skill.name}",
        f"Skill purpose: {skill.description}",
    ]
    for title in required_sections:
        lines.append("")
        lines.append(f"{_format_section_label(title)}:")
        lines.extend(skill.sections[title])
    return "\n".join(lines)


@lru_cache(maxsize=16)
def _load_skill_definition_cached(resolved_path: str) -> SkillDefinition:
    path = Path(resolved_path)
    content = path.read_text(encoding="utf-8")
    frontmatter, body = _split_frontmatter(content, path)
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not name or not description:
        raise ValueError(f"Skill frontmatter is missing name or description: {path}")
    return SkillDefinition(
        path=path,
        name=name,
        description=description,
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
