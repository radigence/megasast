from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('go')
parser = Parser(lang)
code = 'cmd := exec.Command("sh"); other := fmt.Println()'
tree = parser.parse(code.encode())
root = tree.root_node

# Try using #eq? on node text
qstr = '(call_expression function: (selector_expression) @sel (#eq? @sel "exec.Command"))'
try:
    q = Query(lang, qstr)
    cursor = QueryCursor(q)
    matches = list(cursor.matches(root))
    print('OK', len(matches))
    for pat_idx, captures in matches:
        print(captures)
except Exception as e:
    print('FAIL', e)

# Try capturing the selector_expression and checking its text in Python
qstr2 = '(call_expression function: (selector_expression) @sel)'
q2 = Query(lang, qstr2)
cursor2 = QueryCursor(q2)
matches2 = list(cursor2.matches(root))
print('matches2', len(matches2))
for pat_idx, captures in matches2:
    sel = captures['sel'][0]
    print(sel.text.decode())
