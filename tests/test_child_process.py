from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('javascript')
parser = Parser(lang)
code = 'const cp = require("child_process"); cp.exec("ls");'
tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type)
    for c in node.children:
        dump(c, indent+1)
dump(root)

# try query for member_expression property
qstr = '(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "exec")))'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('matches', len(matches))
for pat_idx, captures in matches:
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
