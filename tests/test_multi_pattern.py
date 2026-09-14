from pathlib import Path
from megasast.parser import TreeSitterParser

def test_run_queries_evaluates_every_pattern():
    parser = TreeSitterParser()
    result = parser.parse_file(Path("tests/fixtures/test_scan.py"))
    assert result is not None
    tree, _, lang_name = result
    query = {
        lang_name: (
            '(call function: (identifier) @a (#eq? @a "eval")) @match ; '
            '(call function: (identifier) @b (#eq? @b "exec")) @match'
        )
    }
    matches = parser.run_queries(tree, lang_name, query)
    texts = {m["node"].text.decode() for m in matches}
    # pattern 1: eval("bad"), eval("ignored"); pattern 2: exec("bad")
    assert len(matches) == 3
    assert 'exec("bad")' in texts
