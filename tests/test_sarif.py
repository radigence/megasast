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
