from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

def test_javascript_queries_match_expected_nodes():
    lang = get_language("javascript")
    parser = Parser(lang)
    tree = parser.parse(b'var x = eval(1); var y = new Function("a", "return a"); var z = foo();')
    root = tree.root_node
    queries = {
        "eval": '(call_expression function: (identifier) @f (#eq? @f "eval"))',
        "new_function": '(new_expression constructor: (identifier) @f (#eq? @f "Function"))',
    }
    for query in queries.values():
        qstr = query
        q = Query(lang, qstr)
        cursor = QueryCursor(q)
        matches = list(cursor.matches(root))
        assert len(matches) == 1
