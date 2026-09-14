import json
import jsonschema
from pathlib import Path
from megasast.sarif import findings_to_sarif
from megasast.findings import Finding

def test_sarif_schema_valid():
    f = Finding(
        rule_id="megasast/py-eval",
        message="test",
        path="a.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=4,
        snippet="eval",
        severity="HIGH"
    )
    sarif = findings_to_sarif([f], Path("."))
    # Minimal schema validation: check required top-level keys
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("$schema")
    runs = sarif.get("runs", [])
    assert runs
    run = runs[0]
    assert "tool" in run
    assert "results" in run
    # Validate against vendored schema file
    schema_path = Path("tests/sarif-2.1.0.json")
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(instance=sarif, schema=schema)
    # Check severity mapping
    result = run["results"][0]
    assert result["level"] == "error"
    # Check rule metadata populated
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["name"] == "Python eval() usage"
    assert rule["shortDescription"]["text"] == "Python eval() usage"
    assert rule["fullDescription"]["text"] == "Use of eval() can lead to arbitrary code execution."
    assert "Avoid eval()" in rule["help"]["text"]
    assert rule["properties"]["remediation"]
    assert "Suggested fix:" in result["message"]["text"]
    assert result["properties"]["description"] == rule["fullDescription"]["text"]


def _finding(line: int, rule_id: str = "megasast/rust-command") -> Finding:
    return Finding(
        rule_id=rule_id,
        message="test",
        path="a.rs",
        start_line=line,
        start_column=5,
        end_line=line,
        end_column=20,
        snippet='Command::new("sh")',
        severity="HIGH",
    )


def test_sarif_cwe_owasp_and_fingerprints():
    sarif = findings_to_sarif([_finding(4)], Path("."))
    run = sarif["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "megasast/rust-command")
    assert rule["properties"]["cwe"] == "CWE-78"
    assert "owasp" in rule["properties"]
    fp = run["results"][0]["properties"]["fingerprints"]["megasast"]
    # SHA-256 hex digest is 64 chars (was 40 under SHA-1)
    assert len(fp) == 64
    # schema still valid with the new properties
    schema = json.loads(Path("tests/sarif-2.1.0.json").read_text())
    jsonschema.validate(instance=sarif, schema=schema)


def test_fingerprint_stable_across_line_shifts():
    fp_a = findings_to_sarif([_finding(4)], Path("."))["runs"][0]["results"][0]["properties"]["fingerprints"]["megasast"]
    fp_b = findings_to_sarif([_finding(99)], Path("."))["runs"][0]["results"][0]["properties"]["fingerprints"]["megasast"]
    assert fp_a == fp_b
    fp_other = findings_to_sarif([_finding(4, rule_id="megasast/py-eval")], Path("."))["runs"][0]["results"][0]["properties"]["fingerprints"]["megasast"]
    assert fp_other != fp_a
