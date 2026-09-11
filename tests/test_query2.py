from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('javascript')
parser = Parser(lang)
code = b'var x = eval(1); var y = foo(2);'
tree = parser.parse(code)
root = tree.root_node

qstr = '(call_expression function: (identifier) @f (#eq? @f "eval"))'
q = Query(lang, qstr)
cursor = QueryCursor(q)
for pat_idx, captures in cursor.matches(root):
    print('match', captures)
    for name, nodes in captures.items():
        for n in nodes:
            print(' ', name, n.text.decode())
