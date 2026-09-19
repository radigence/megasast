"""Regenerate RULES.md from the megasast rule registry (single source of truth).

Usage (requires megasast installed, e.g. `pip install -e .[dev]`):

    python scripts/generate_rules_md.py
"""
from pathlib import Path
import re

from megasast.rules.registry import RULES

ROOT = Path(__file__).resolve().parent.parent


def gh_anchor(title):
    # Match GitHub's heading slugger: lowercase, drop anything that is not
    # alphanumeric/space/hyphen/underscore, spaces become hyphens.
    return re.sub(r"[^a-z0-9 _-]", "", title.lower()).replace(" ", "-")

FAMILIES = [
    ("Python", {"python"}),
    ("JavaScript / TypeScript", {"javascript", "typescript"}),
    ("Java", {"java"}),
    ("C / C++", {"c", "cpp"}),
    ("Go", {"go"}),
    ("PHP", {"php"}),
    ("Rust", {"rust"}),
]

LANG_LABELS = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "go": "go",
    "php": "php",
    "rust": "rust",
}


def section_of(rule):
    langs = set(rule.languages)
    for title, family in FAMILIES:
        if langs <= family:
            return title
    return "Cross-language"


def esc(text):
    return text.replace("|", "\\|").replace("\n", " ")


def render(rule):
    meta = [f"**Severity:** {rule.severity}",
            f"**Languages:** {', '.join(LANG_LABELS.get(l, l) for l in rule.languages)}"]
    if rule.cwe:
        meta.append(f"**CWE:** {rule.cwe}")
    if rule.owasp:
        meta.append(f"**OWASP:** {rule.owasp}")
    if rule.tags:
        meta.append(f"**Tags:** {', '.join(rule.tags)}")
    lines = [f"### `{rule.id}` — {esc(rule.name)}", ""]
    lines.append(" · ".join(meta))
    lines.append("")
    lines.append(esc(rule.description))
    lines.append("")
    if rule.remediation:
        lines.append(f"**Remediation:** {esc(rule.remediation)}")
        lines.append("")
    if rule.message and rule.message != rule.description:
        lines.append(f"**Finding message:** {esc(rule.message)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main():
    ordered_sections = [t for t, _ in FAMILIES] + ["Cross-language"]
    grouped = {title: [] for title in ordered_sections}
    for rule in RULES:
        grouped[section_of(rule)].append(rule)

    out = ["# megasast rule catalog", ""]
    out.append("Full per-rule reference: description, severity, CWE/OWASP mapping,")
    out.append("and remediation guidance. The summary table lives in [README.md](README.md#rules).")
    out.append("")
    out.append("## Contents")
    out.append("")
    for title in ordered_sections:
        rules = grouped[title]
        if not rules:
            continue
        anchor = gh_anchor(title)
        out.append(f"- [{title} ({len(rules)})](#{anchor})")
    out.append("")

    for title in ordered_sections:
        rules = grouped[title]
        if not rules:
            continue
        out.append(f"## {title}")
        out.append("")
        for rule in rules:
            out.append(render(rule))
            out.append("")

    target = ROOT / "RULES.md"
    target.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8", newline="\n")

    total = sum(len(v) for v in grouped.values())
    print(f"wrote {target} with {total} rules")
    for title in ordered_sections:
        print(f"  {title}: {len(grouped[title])}")


if __name__ == "__main__":
    main()
