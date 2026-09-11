from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query

lang = get_language('javascript')
parser = Parser(lang)
code = b'var x = eval(1);'
tree = parser.parse(code)
root = tree.root_node

# print node types
def dump(node, indent=0):
    print('  '*indent, node.type, node.text.decode()[:40])
    for c in node.children:
        dump(c, indent+1)
dump(root)

# Try queries
queries = [
    '(call_expression function: (identifier) @f)',
    '(call_expression function: (identifier) @f (#eq? @f "eval"))',
    '(call_expression function: (identifier) @f) @f',
]

for qstr in queries:
    try:
        q = Query(lang, qstr)
        print('OK', qstr)
        # iterate
        for pat_idx, captures in q.matches(root):
            print('  match', captures)
    except Exception as e:
        print('FAIL', qstr, e)
