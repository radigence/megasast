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

qstr = '(method_invocation method_name: (identifier) @m)'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('matches', len(matches))
for pat_idx, captures in matches:
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
