from pathlib import Path
from megasast.parser import TreeSitterParser
from megasast.engine import scan_file

def test_eval_rule_fires():
    parser = TreeSitterParser()
    path = Path("tests/fixtures/py/sample_eval.py")
    findings = scan_file(path, parser)
    ids = [f.rule_id for f in findings]
    assert "megasast/py-eval" in ids
    # verify severity is populated
    severities = [f.severity for f in findings if f.rule_id == "megasast/py-eval"]
    assert severities and severities[0] == "HIGH"
    # verify snippet and location
    f = next(x for x in findings if x.rule_id == "megasast/py-eval")
    assert f.start_line == 1
    assert "eval" in f.snippet
