import pytest

from megasast.discovery import discover, _is_within_root


def test_is_within_root_rejects_paths_outside_root(tmp_path):
    root = (tmp_path / "root").resolve()
    root.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    inside = root / "a.py"
    inside.write_text("x=1\n", encoding="utf-8")
    outside_file = outside / "secret.py"
    outside_file.write_text("top secret\n", encoding="utf-8")

    assert _is_within_root(inside, root) is True
    assert _is_within_root(outside_file, root) is False


def test_discover_does_not_follow_symlinks_escaping_root(tmp_path):
    outside = tmp_path / "secrets"
    outside.mkdir()
    secret = outside / "id_rsa"
    secret.write_text("PRIVATE KEY MATERIAL\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.py").write_text("x=1\n", encoding="utf-8")
    link = root / "leak.py"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError, AttributeError) as e:
        pytest.skip(f"cannot create symlink in this environment: {e}")

    names = {p.name for p in discover(root)}
    assert "app.py" in names
    # The symlink that points outside the scan root must not be followed.
    assert "leak.py" not in names


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
