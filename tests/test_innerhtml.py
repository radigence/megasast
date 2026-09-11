from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('javascript')
parser = Parser(lang)
code = 'el.innerHTML = "<b>hi</b>";'
tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type, node.text.decode(errors='replace')[:60])
    for c in node.children:
        dump(c, indent+1)
dump(root)

queries = [
'(assignment_expression left: (member_expression property: (property_identifier) @p))',
'(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML")))',
]

for qstr in queries:
    q = Query(lang, qstr)
    cursor = QueryCursor(q)
    print('\nQuery:', qstr)
    for pat_idx, captures in cursor.matches(root):
        print(' match', captures)
        for name, nodes in captures.items():
            for n in nodes:
                print('  ', name, n.text.decode())
