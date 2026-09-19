from pathlib import Path
from megasast.parser import TreeSitterParser
from megasast.engine import scan_file
from megasast.rules.registry import RULES

PATH = Path("tests/fixtures/test.rs")

def test_rust_command_fires():
    parser = TreeSitterParser()
    findings = scan_file(PATH, parser)
    ids = [f.rule_id for f in findings]
    assert "megasast/rust-command" in ids
    # both Command::new and std::process::Command::new are flagged
    f = [x for x in findings if x.rule_id == "megasast/rust-command"]
    assert len(f) == 2
    severities = [x.severity for x in f]
    assert severities and all(s == "HIGH" for s in severities)
    first = next(x for x in f if x.start_line == 4)
    assert "Command::new" in first.snippet

def test_rust_unsafe_fires():
    parser = TreeSitterParser()
    findings = scan_file(PATH, parser)
    f = [x for x in findings if x.rule_id == "megasast/rust-unsafe"]
    assert len(f) == 1
    assert f[0].start_line == 8
    assert f[0].severity == "LOW"
    assert "unsafe" in f[0].snippet

def test_rust_transmute_fires():
    parser = TreeSitterParser()
    findings = scan_file(PATH, parser)
    f = [x for x in findings if x.rule_id == "megasast/rust-transmute"]
    assert len(f) == 1
    assert f[0].start_line == 9
    assert f[0].severity == "MEDIUM"
    assert "transmute" in f[0].snippet

def test_rust_rules_registered():
    ids = {r.id for r in RULES}
    assert {"megasast/rust-command", "megasast/rust-unsafe", "megasast/rust-transmute"} <= ids
    for r in RULES:
        if r.id.startswith("megasast/rust-"):
            assert "rust" in r.languages
