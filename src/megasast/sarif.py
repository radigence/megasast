import json
from pathlib import Path
from megasast.findings import Finding
from megasast.rules.registry import RULES

def _rel_uri(path: str, root: Path) -> str:
    p = Path(path)
    try:
        rel = p.relative_to(root)
    except ValueError:
        rel = p
    return str(rel).replace("\\", "/")

def findings_to_sarif(findings: list[Finding], root: Path, tool_version: str = "0.1.0"):
    rules_map = {}
    results = []
    # build lookup for rule metadata
    rule_lookup = {r.id: r for r in RULES}
    # Ensure all rules are present even with no findings
    for rule in RULES:
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
            rules_map[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": default_level},
                "properties": {"tags": tags},
                "helpUri": f"https://github.com/matt/megasast#rule-{rule_id}",
            }
    for f in findings:
        rule_id = f.rule_id
        # rules_map already populated with all rules

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
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _rel_uri(f.path, root)},
                    "region": {
                        "startLine": f.start_line,
                        "startColumn": f.start_column,
                        "endLine": f.end_line,
                        "endColumn": f.end_column,
                        "snippet": {"text": f.snippet}
                    }
                }
            }]
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "megasast",
                    "informationUri": "https://github.com/matt/megasast",
                    "version": tool_version,
                    "rules": list(rules_map.values())
                }
            },
            "results": results,
            "originalUriBaseIds": {
                "ROOT": {"uri": ""}
            }
        }]
    }
    return sarif
