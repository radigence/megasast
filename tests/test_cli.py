from pathlib import Path

from megasast.cli import _apply_baseline, _finding_to_json, _flatten_worker_results
from megasast.findings import Finding
from megasast.sarif import findings_to_sarif
from megasast.rules.python_rules import PYTHON_EVAL


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


def _finding(snippet="eval(x)", line=3):
    return Finding(
        rule_id="megasast/py-eval",
        message="test",
        path="a.py",
        start_line=line,
        start_column=1,
        end_line=line,
        end_column=10,
        snippet=snippet,
        severity="HIGH",
    )


def _baseline_sarif():
    return findings_to_sarif([_finding()], Path("."))


def test_baseline_positional_match_filters_known_finding():
    baseline = _baseline_sarif()
    # Same rule + path + line/column as the baseline result → not new.
    assert _apply_baseline([_finding()], baseline, Path(".")) == []


def test_baseline_fingerprint_match_survives_line_shift():
    baseline = _baseline_sarif()
    # Same finding moved 20 lines down: positional key no longer matches,
    # but the shift-stable fingerprint does, so it is still filtered.
    assert _apply_baseline([_finding(line=23)], baseline, Path(".")) == []


def test_baseline_reports_new_and_distinct_findings():
    baseline = _baseline_sarif()
    remaining = _apply_baseline(
        [
            _finding(snippet="different code", line=5),
            _finding(snippet="other new code", line=42),
        ],
        baseline,
        Path("."),
    )
    assert len(remaining) == 2
