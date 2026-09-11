from megasast.config import load_config


def test_load_config_finds_nearest_parent_configuration(tmp_path):
    (tmp_path / "megasast.toml").write_text(
        "[megasast.rules]\nseverity = ['HIGH']\n", encoding="utf-8"
    )
    nested = tmp_path / "one" / "two"
    nested.mkdir(parents=True)

    assert load_config(nested) == {"rules": {"severity": ["HIGH"]}}
