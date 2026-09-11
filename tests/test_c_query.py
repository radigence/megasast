from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('c')
parser = Parser(lang)
code = 'int main(){ system("ls"); strcpy(a,b); }'
tree = parser.parse(code.encode())
root = tree.root_node

qstr = '(call_expression function: (identifier) @f (#eq? @f "system"))'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('system matches', len(matches))
for pat_idx, captures in matches:
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())

qstr2 = '(call_expression function: (identifier) @f (#eq? @f "strcpy"))'
q2 = Query(lang, qstr2)
cursor2 = QueryCursor(q2)
matches2 = list(cursor2.matches(root))
print('strcpy matches', len(matches2))
for pat_idx, captures in matches2:
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
