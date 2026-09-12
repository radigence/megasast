import pytest

from megasast.engine import scan_file
from megasast.parser import TreeSitterParser


@pytest.mark.parametrize(
    ("filename", "source", "expected_rule"),
    [
        ("sample.py", "import ssl\nssl._create_unverified_context()\n", "megasast/py-ssl-unverified-context"),
        ("sample.py", "import hashlib\nhashlib.md5(b'data')\n", "megasast/py-hashlib-md5"),
        ("sample.py", "import hashlib\nhashlib.sha1(b'data')\n", "megasast/py-hashlib-sha1"),
        ("sample.py", "import tempfile\ntempfile.mktemp()\n", "megasast/py-mktemp"),
        ("sample.js", "child_process.execSync(command);\n", "megasast/js-child-process-exec-sync"),
        ("sample.js", "document.write(content);\n", "megasast/js-document-write"),
        ("Sample.java", "class Sample { void f() { MessageDigest.getInstance(\"MD5\"); } }\n", "megasast/java-message-digest-md5"),
        ("Sample.java", "class Sample { void f() { MessageDigest.getInstance(\"SHA-1\"); } }\n", "megasast/java-message-digest-sha1"),
        ("sample.go", "package sample\nimport \"crypto/md5\"\n", "megasast/go-crypto-md5"),
        ("sample.go", "package sample\nimport \"crypto/sha1\"\n", "megasast/go-crypto-sha1"),
        ("sample.c", "void f(char *s) { gets(s); sprintf(s, \"x\"); strcat(s, \"x\"); }\n", "megasast/c-gets"),
        ("sample.c", "void f(char *s) { sprintf(s, \"x\"); }\n", "megasast/c-sprintf"),
        ("sample.c", "void f(char *s) { strcat(s, \"x\"); }\n", "megasast/c-strcat"),
        ("sample.php", "<?php md5($value); sha1($value); ?>\n", "megasast/php-md5"),
        ("sample.php", "<?php sha1($value); ?>\n", "megasast/php-sha1"),
    ],
)
def test_new_rules_match_representative_code(tmp_path, filename, source, expected_rule):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={expected_rule})

    assert [finding.rule_id for finding in findings] == [expected_rule]


def test_subprocess_shell_rule_does_not_match_shell_false(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("import subprocess\nsubprocess.Popen(['echo', 'safe'], shell=False)\n", encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={"megasast/py-subprocess-shell"})

    assert findings == []


def test_child_process_exec_sync_rule_does_not_match_other_objects(tmp_path):
    path = tmp_path / "sample.js"
    path.write_text("runner.execSync(command);\n", encoding="utf-8")

    findings = scan_file(path, TreeSitterParser(), allowed_rules={"megasast/js-child-process-exec-sync"})

    assert findings == []
