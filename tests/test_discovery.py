from megasast.discovery import discover


def test_nested_gitignore_negation_overrides_parent_rule(tmp_path):
    (tmp_path / ".gitignore").write_text("*.py\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".gitignore").write_text("!keep.py\n", encoding="utf-8")
    (nested / "keep.py").write_text("pass\n", encoding="utf-8")
    (nested / "ignore.py").write_text("pass\n", encoding="utf-8")

    discovered = {path.relative_to(tmp_path).as_posix() for path in discover(tmp_path)}

    assert "nested/keep.py" in discovered
    assert "nested/ignore.py" not in discovered
