from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('python')
parser = Parser(lang)
code = 'os.system("ls")'
tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type, node.text.decode(errors='replace')[:40])
    for c in node.children:
        dump(c, indent+1)
dump(root)

qstr = '(call function: (attribute value: (identifier) @obj attribute: (identifier) @m))'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('matches', len(matches))
for pat_idx, captures in matches:
    print(captures)
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
