from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

def test(lang_name, code, queries):
    lang = get_language(lang_name)
    parser = Parser(lang)
    tree = parser.parse(code.encode())
    root = tree.root_node
    for name, qstr in queries.items():
        q = Query(lang, qstr)
        cursor = QueryCursor(q)
        matches = list(cursor.matches(root))
        print(lang_name, name, 'matches', len(matches))
        for pat_idx, captures in matches:
            for nname, nodes in captures.items():
                for n in nodes:
                    print(' ', nname, n.text.decode())

test('javascript', 'var x = eval(1); var y = new Function("a","return a"); var z = foo();', {
    'eval': '(call_expression function: (identifier) @f (#eq? @f "eval"))',
    'new_function': '(new_expression constructor: (identifier) @f (#eq? @f "Function"))',
    'innerhtml': '(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML")))',
})
