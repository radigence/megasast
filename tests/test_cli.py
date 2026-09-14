import sys
from pathlib import Path

import pytest

from megasast.cli import _finding_to_json, _flatten_worker_results, main
from megasast.findings import Finding
from megasast.rules.python_rules import PYTHON_EVAL

FIXTURES = Path(__file__).parent / "fixtures"


def test_flatten_worker_results_returns_findings_not_per_file_lists():
    finding = Finding(
        rule_id="megasast/py-eval",
        message="test",
        path="test.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=5,
        snippet="eval",
        severity="HIGH",
    )

    assert _flatten_worker_results([[finding], []]) == [finding]


def test_json_finding_includes_rule_description_and_remediation():
    finding = Finding(
        rule_id=PYTHON_EVAL.id,
        message=PYTHON_EVAL.message,
        path="test.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=5,
        snippet="eval",
        severity="HIGH",
    )

    result = _finding_to_json(finding, PYTHON_EVAL)

    assert result["description"] == PYTHON_EVAL.description
    assert result["remediation"] == PYTHON_EVAL.remediation
    assert result["suggested_fix"] == PYTHON_EVAL.remediation


def test_scan_single_file_reports_findings(capsys, monkeypatch):
    target = FIXTURES / "py" / "sample_eval.py"
    monkeypatch.setattr(sys, "argv", ["megasast", "scan", str(target), "--format", "text"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "megasast/py-eval" in out
    assert "sample_eval.py" in out
