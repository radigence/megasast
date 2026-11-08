from megasast.engine import scan_file
from megasast.parser import TreeSitterParser


def test_multi_capture_rule_emits_one_finding_at_the_call(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("import os\nos.system('echo hello')\n", encoding="utf-8")

    findings = scan_file(source, TreeSitterParser(), allowed_rules={"megasast/py-os-system"})

    assert len(findings) == 1
    assert findings[0].start_line == 2
    assert findings[0].start_column == 1
    assert findings[0].snippet == "os.system('echo hello')"


def _scan(source: str, tmp_path):
    source_file = tmp_path / "example.py"
    source_file.write_text(source, encoding="utf-8")
    return scan_file(source_file, TreeSitterParser(), allowed_rules={"megasast/py-os-system"})


def test_trailing_suppression_comment_hides_finding(tmp_path):
    findings = _scan("os.system('echo hello')  # megasast:ignore megasast/py-os-system\n", tmp_path)
    assert findings == []


def test_preceding_line_suppression_hides_finding(tmp_path):
    findings = _scan(
        "# megasast:ignore megasast/py-os-system\nos.system('echo hello')\n",
        tmp_path,
    )
    assert findings == []


def test_ignore_comment_without_rule_id_does_not_suppress(tmp_path):
    findings = _scan("# megasast:ignore someone-else-rule\nos.system('echo hello')\n", tmp_path)
    # The comment names a different rule, so our rule keeps firing.
    assert len(findings) == 1


def test_distant_ignore_comment_does_not_suppress_unrelated_finding(tmp_path):
    # Regression: the old 5-line suppression window silenced findings that
    # were far below an unrelated ignore comment. Suppression is now
    # line-anchored (own line or the immediately preceding line).
    source = (
        "# megasast:ignore megasast/py-os-system\n"
        "x = 1\n"
        "y = 2\n"
        "z = 3\n"
        "os.system('echo hello')\n"
    )
    findings = _scan(source, tmp_path)
    assert len(findings) == 1


def test_suppression_of_one_finding_leaves_next_one_active(tmp_path):
    # Suppressing the first call must not silence the second (lines are
    # anchored per finding, not per rule).
    source = (
        "os.system('ls')  # megasast:ignore megasast/py-os-system\n"
        "os.system('ls')\n"
    )
    findings = _scan(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].start_line == 2


def test_string_literal_containing_token_does_not_suppress(tmp_path):
    # Regression: suppression comments must be real comment nodes, not any
    # line whose text contains the token — string-literal lookalikes must
    # not silence a finding below them.
    source = (
        'banner = "# megasast:ignore megasast/py-os-system"\n'
        "os.system('echo hello')\n"
    )
    findings = _scan(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].start_line == 2
