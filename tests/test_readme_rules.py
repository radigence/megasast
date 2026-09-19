from pathlib import Path

from megasast.rules.registry import RULES

def test_readme_lists_every_registered_rule():
    readme = Path("README.md").read_text(encoding="utf-8")
    missing = [r.id for r in RULES if r.id not in readme]
    assert not missing, f"README.md is missing rules: {missing}"

def test_rules_md_lists_every_registered_rule():
    rules_md = Path("RULES.md").read_text(encoding="utf-8")
    missing = [r.id for r in RULES if r.id not in rules_md]
    assert not missing, f"RULES.md is missing rules: {missing}"
