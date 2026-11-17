import json
import sys
from pathlib import Path

import pytest

from megasast.cli import main
from megasast.engine import scan_file
from megasast.parser import TreeSitterParser, known_languages, lang_active
from megasast.rules.registry import RULES

FIXTURES = Path(__file__).parent / "fixtures"
PY_SAMPLE = FIXTURES / "py" / "sample_eval.py"
JS_SAMPLE = FIXTURES / "test_js.js"


def test_known_languages_covers_every_rule_language():
    known = known_languages()
    for rule in RULES:
        assert set(rule.languages) <= known, rule.id


def test_lang_active_excluded_drops_matching_grammar():
    assert lang_active("python", excluded={"python"}) is False
    assert lang_active("javascript", excluded={"python"}) is True


def test_lang_active_allowed_keeps_only_listed_grammars():
    assert lang_active("python", allowed={"python"}) is True
    assert lang_active("javascript", allowed={"python"}) is False


def test_lang_active_alias_maps_grammar_to_rule_language():
    # tsx files run the typescript rule set, so filtering "typescript"
    # filters tsx files too. The reverse is file-scoped: filtering "tsx"
    # targets tsx files and leaves .ts files (grammar "typescript") alone.
    assert lang_active("tsx", excluded={"typescript"}) is False
    assert lang_active("tsx", excluded={"tsx"}) is False
    assert lang_active("typescript", excluded={"tsx"}) is True
    assert lang_active("tsx", allowed={"typescript"}) is True
    assert lang_active("typescript", allowed={"tsx"}) is False
    # Unrelated grammars are unaffected.
    assert lang_active("javascript", excluded={"typescript"}) is True


def test_parse_file_skips_excluded_language():
    parser = TreeSitterParser()
    assert parser.parse_file(PY_SAMPLE, excluded_languages={"python"}) is None
    assert parser.parse_file(JS_SAMPLE, excluded_languages={"python"}) is not None


def test_scan_file_excluded_language_suppresses_findings():
    findings = scan_file(PY_SAMPLE, TreeSitterParser(), excluded_languages={"python"})
    assert findings == []


def test_scan_file_allowed_language_keeps_match():
    parser = TreeSitterParser()
    findings = scan_file(PY_SAMPLE, parser, allowed_languages={"python"})
    assert any(f.rule_id == "megasast/py-eval" for f in findings)
    assert scan_file(JS_SAMPLE, parser, allowed_languages={"python"}) == []


def test_excluding_typescript_covers_tsx_files(tmp_path):
    tsx = tmp_path / "App.tsx"
    tsx.write_text('eval("1+1")\n', encoding="utf-8")
    base = [f.rule_id for f in scan_file(tsx, TreeSitterParser())]
    assert "megasast/js-eval" in base
    assert scan_file(tsx, TreeSitterParser(), excluded_languages={"typescript"}) == []
    remaining = [f.rule_id for f in scan_file(tsx, TreeSitterParser(), excluded_languages={"javascript"})]
    assert "megasast/js-eval" in remaining


def test_header_scanned_under_both_grammars_respects_per_language_filter(tmp_path):
    header = tmp_path / "sample.h"
    header.write_text(
        "#include <string.h>\nvoid f(char *d, char *s) { strcpy(d, s); }\n", encoding="utf-8"
    )
    base = [f.rule_id for f in scan_file(header, TreeSitterParser())]
    assert "megasast/c-strcpy" in base
    # Excluding C leaves the C++ grammar pair, so the finding still fires.
    remaining = [f.rule_id for f in scan_file(header, TreeSitterParser(), excluded_languages={"c"})]
    assert "megasast/c-strcpy" in remaining
    # Excluding both grammars disables the file entirely.
    assert scan_file(header, TreeSitterParser(), excluded_languages={"c", "cpp"}) == []


def test_cli_no_language_excludes_language(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(PY_SAMPLE), "--format", "text", "--no-language", "python",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "megasast/py-eval" not in capsys.readouterr().out


def test_cli_language_allow_list(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(PY_SAMPLE), "--format", "text", "--language", "javascript",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "megasast/py-eval" not in capsys.readouterr().out


def test_cli_unknown_language_rejected(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(PY_SAMPLE), "--format", "text", "--no-language", "pythonn",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert "unknown language" in capsys.readouterr().err


def test_cli_unknown_language_lists_valid_choices(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(PY_SAMPLE), "--format", "text", "--language", "cobol",
    ])
    with pytest.raises(SystemExit):
        main()
    err = capsys.readouterr().err
    for known in ("python", "javascript", "go", "rust", "c", "cpp", "java", "php"):
        assert known in err


def test_config_languages_exclude_applies(capsys, monkeypatch, tmp_path):
    (tmp_path / "sample.py").write_text('x = eval("1+1")\n', encoding="utf-8")
    (tmp_path / "megasast.toml").write_text(
        "[megasast.languages]\nexclude = ['python']\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["megasast", "scan", str(tmp_path), "--format", "text"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "megasast/py-eval" not in capsys.readouterr().out


def test_config_languages_only_applies(capsys, monkeypatch, tmp_path):
    (tmp_path / "sample.py").write_text('x = eval("1+1")\n', encoding="utf-8")
    (tmp_path / "sample.js").write_text('var a = eval("x");\n', encoding="utf-8")
    (tmp_path / "megasast.toml").write_text(
        "[megasast.languages]\nonly = ['javascript']\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["megasast", "scan", str(tmp_path), "--format", "text"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "megasast/py-eval" not in out
    assert "megasast/js-eval" in out


def test_cli_no_language_overrides_config_exclude(capsys, monkeypatch, tmp_path):
    (tmp_path / "sample.py").write_text('x = eval("1+1")\n', encoding="utf-8")
    (tmp_path / "megasast.toml").write_text(
        "[megasast.languages]\nexclude = ['python']\n", encoding="utf-8"
    )
    # Per-key precedence, same as --rule/--no-rule: an explicit CLI value
    # replaces the config value for that key.
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(tmp_path), "--format", "text", "--no-language", "javascript",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "megasast/py-eval" in capsys.readouterr().out


def test_config_unknown_language_warns(capsys, monkeypatch, tmp_path):
    (tmp_path / "sample.py").write_text('x = eval("1+1")\n', encoding="utf-8")
    (tmp_path / "megasast.toml").write_text(
        "[megasast.languages]\nexclude = ['pythonn']\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["megasast", "scan", str(tmp_path), "--format", "text"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "unknown language" in captured.err
    assert "megasast/py-eval" in captured.out


def test_sarif_omits_rules_for_excluded_language(capsys, monkeypatch, tmp_path):
    (tmp_path / "sample.py").write_text('x = eval("1+1")\n', encoding="utf-8")
    out = tmp_path / "results.sarif"
    monkeypatch.setattr(sys, "argv", [
        "megasast", "scan", str(tmp_path), "--format", "sarif",
        "-o", str(out), "--no-language", "python",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    sarif = json.loads(out.read_text(encoding="utf-8"))
    rule_ids = {r["id"] for run in sarif["runs"] for r in run["tool"]["driver"]["rules"]}
    assert "megasast/py-eval" not in rule_ids
    assert "megasast/js-eval" in rule_ids
    assert sarif["runs"][0]["results"] == []
