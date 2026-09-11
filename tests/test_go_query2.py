from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('go')
parser = Parser(lang)
code = 'cmd := exec.Command("sh")'
tree = parser.parse(code.encode())
root = tree.root_node

qstr = '(call_expression function: (selector_expression) @f)'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
for pat_idx, captures in matches:
    f_node = captures['f'][0]
    print('selector', f_node.text.decode())
    # children
    for c in f_node.children:
        print(' child', c.type, c.text.decode())
