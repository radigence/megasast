from megasast.cli import _flatten_worker_results
from megasast.findings import Finding


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
