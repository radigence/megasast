from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('java')
parser = Parser(lang)
code = '''
class A {
    void f() {
        Runtime.getRuntime().exec("cmd");
    }
}
'''
tree = parser.parse(code.encode())
root = tree.root_node

# dump
def dump(node, indent=0):
    print('  '*indent, node.type)
    for c in node.children:
        dump(c, indent+1)
dump(root)

qstr = '(method_invocation name: (identifier) @m)'
try:
    q = Query(lang, qstr)
    print('query ok')
    cursor = QueryCursor(q)
    matches = list(cursor.matches(root))
    print('matches', len(matches))
    for pat_idx, captures in matches:
        for name, nodes in captures.items():
            for n in nodes:
                print(name, n.text.decode())
except Exception as e:
    print('error', e)

# Try more specific
qstr2 = '(method_invocation object: (method_invocation) @inner name: (identifier) @m (#eq? @m "exec"))'
try:
    q2 = Query(lang, qstr2)
    print('query2 ok')
    cursor2 = QueryCursor(q2)
    matches2 = list(cursor2.matches(root))
    print('matches2', len(matches2))
    for pat_idx, captures in matches2:
        print(captures)
except Exception as e:
    print('error2', e)
