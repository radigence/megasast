import hashlib
import re
from pathlib import Path

from megasast.findings import Finding
from megasast.version import __version__
from megasast.rules.registry import RULES

# Per-rule links point at the generated rule catalog. The anchors are the
# GitHub heading slugs of RULES.md's `### <id> — <name>` headings, computed
# with the same algorithm as scripts/generate_rules_md.py.
RULES_MD_URL = "https://github.com/radigence/megasast/blob/main/RULES.md"

def _gh_anchor(title: str) -> str:
    # Match GitHub's heading slugger (and gh_anchor in
    # scripts/generate_rules_md.py): lowercase, drop anything that is not
    # alphanumeric/space/hyphen/underscore, spaces become hyphens.
    return re.sub(r"[^a-z0-9 _-]", "", title.lower()).replace(" ", "-")

def rule_help_uri(rule) -> str:
    heading = f"`{rule.id}` — {rule.name}"
    return f"{RULES_MD_URL}#{_gh_anchor(heading)}"

def _rel_uri(path: str, root: Path) -> str:
    p = Path(path)
    try:
        rel = p.relative_to(root)
    except ValueError:
        rel = p
    return str(rel).replace("\\", "/")

def _fingerprint(rule_id: str, uri: str, snippet: str) -> str:
    # Stable across line-number shifts: keyed on rule, path, normalized snippet.
    # SHA-256 (not SHA-1) since SHA-1 is collision-broken.
    normalized = " ".join((snippet or "").split())
    return hashlib.sha256(f"{rule_id}|{uri}|{normalized}".encode("utf-8")).hexdigest()

def findings_to_sarif(findings: list[Finding], root: Path, active_rule_ids: set | None = None, tool_version: str = __version__) -> dict:
    """Build a SARIF 2.1.0 report.

    ``active_rule_ids`` mirrors the scanning filters: when the scan ran with
    ``--rule``/``--no-rule``/severity restrictions, only those rules are
    published in the report, so downstream consumers (GitHub code scanning,
    DefectDojo) don't show disabled rules as suspiciously result-less.
    ``None`` means the full built-in catalog.
    """
    rules_map = {}
    results = []
    # build lookup for rule metadata
    rule_lookup = {r.id: r for r in RULES}
    # Ensure all rules are present even with no findings
    for rule in RULES:
        if active_rule_ids is not None and rule.id not in active_rule_ids:
            continue
        rule_id = rule.id
        if rule_id not in rules_map:
            name = rule.name
            description = rule.description
            tags = rule.tags
            severity = rule.severity
            sev_lower = str(severity).lower()
            if sev_lower == "high":
                default_level = "error"
            elif sev_lower == "medium":
                default_level = "warning"
            elif sev_lower == "low":
                default_level = "note"
            else:
                default_level = "warning"
            rule_properties = {"tags": tags}
            if rule.cwe:
                rule_properties["cwe"] = rule.cwe
            if rule.owasp:
                rule_properties["owasp"] = rule.owasp
            rule_properties["description"] = description
            rule_properties["remediation"] = rule.remediation
            rule_properties["severity"] = severity
            rules_map[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": description},
                "help": {"text": rule.remediation or description},
                "defaultConfiguration": {"level": default_level},
                "properties": rule_properties,
                "helpUri": rule_help_uri(rule),
            }
    for f in findings:
        rule_id = f.rule_id
        rule = rule_lookup.get(rule_id)
        description = rule.description if rule else ""
        remediation = rule.remediation if rule else ""

        # map severity from finding
        sev_lower = str(f.severity).lower()
        if sev_lower == "high":
            level = "error"
        elif sev_lower == "medium":
            level = "warning"
        elif sev_lower == "low":
            level = "note"
        else:
            level = "warning"
        uri = _rel_uri(f.path, root)
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": " ".join(
                    part for part in (
                        f.message,
                        description,
                        f"Suggested fix: {remediation}" if remediation else "",
                    ) if part
                )
            },
            "properties": {
                "description": description,
                "remediation": remediation,
                "tags": rule.tags if rule else [],
                "severity": f.severity,
                "fingerprints": {"megasast": _fingerprint(rule_id, uri, f.snippet)},
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": f.start_line,
                        "startColumn": f.start_column,
                        "endLine": f.end_line,
                        "endColumn": f.end_column,
                        "snippet": {"text": f.snippet}
                    }
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "megasast",
                    "informationUri": "https://github.com/radigence/megasast",
                    "version": tool_version,
                    "rules": list(rules_map.values())
                }
            },
            "results": results,
        }]
    }
    return sarif
