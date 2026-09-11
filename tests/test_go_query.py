from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('go')
parser = Parser(lang)
code = 'cmd := exec.Command("sh")'
tree = parser.parse(code.encode())
root = tree.root_node

queries = [
    '(call_expression function: (selector_expression) @f)',
    '(call_expression function: (selector_expression value: (identifier) @pkg field: (field_identifier) @field))',
]

for qstr in queries:
    try:
        q = Query(lang, qstr)
        cursor = QueryCursor(q)
        matches = list(cursor.matches(root))
        print('OK', qstr, len(matches))
        for pat_idx, captures in matches:
            print(' ', captures)
            for name, nodes in captures.items():
                for n in nodes:
                    print('  ', name, n.text.decode())
    except Exception as e:
        print('FAIL', qstr, e)
