from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('python')
parser = Parser(lang)
code = '''
import os
import subprocess
import pickle
import yaml

eval("1+1")
exec("print(1)")
os.system("ls")
subprocess.Popen("ls", shell=True)
pickle.load(open("a"))
yaml.load(open("b"))
'''

tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type)
    for c in node.children:
        dump(c, indent+1)

# find os.system
qstr = '(call function: (attribute) @a)'
q = Query(lang, qstr)
cursor = QueryCursor(q)
matches = list(cursor.matches(root))
print('attributes', len(matches))
for pat_idx, captures in matches[:10]:
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode(), 'children:', [c.type for c in n.children])
