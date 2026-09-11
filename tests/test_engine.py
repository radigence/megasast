from pathlib import Path

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
