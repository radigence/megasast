from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('python')
parser = Parser(lang)
code = 'os.system("ls")'
tree = parser.parse(code.encode())
root = tree.root_node

qstr = '(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) @a)'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('matches', len(matches))
for pat_idx, captures in matches:
    print(captures)
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
