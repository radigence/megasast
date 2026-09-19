from pathlib import Path
from megasast.parser import TreeSitterParser
from megasast.engine import scan_file

PATH = Path("tests/fixtures/sample.ts")
EXPECTED = {
    "megasast/js-eval": "HIGH",
    "megasast/js-new-function": "HIGH",
    "megasast/js-innerhtml": "MEDIUM",
    "megasast/js-child-process-exec": "HIGH",
}

def test_typescript_rules_fire():
    parser = TreeSitterParser()
    findings = scan_file(PATH, parser)
    ids = {f.rule_id for f in findings}
    assert set(EXPECTED) <= ids
    for rule_id, severity in EXPECTED.items():
        f = next(x for x in findings if x.rule_id == rule_id)
        assert f.severity == severity
        assert "userInput" in f.snippet
