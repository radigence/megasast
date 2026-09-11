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

queries = {
    'eval': '(call function: (identifier) @f (#eq? @f "eval"))',
    'exec': '(call function: (identifier) @f (#eq? @f "exec"))',
    'os.system': '(call function: (attribute value: (identifier) @obj (#eq? @obj "os") attribute: (identifier) @m (#eq? @m "system")))',
    'pickle.load': '(call function: (attribute value: (identifier) @obj (#eq? @obj "pickle") attribute: (identifier) @m (#eq? @m "load")))',
    'yaml.load': '(call function: (attribute value: (identifier) @obj (#eq? @obj "yaml") attribute: (identifier) @m (#eq? @m "load")))',
}

for name, qstr in queries.items():
    q = Query(lang, qstr)
    cursor = QueryCursor(q)
    matches = list(cursor.matches(root))
    print(name, len(matches))
    for pat_idx, captures in matches:
        for nname, nodes in captures.items():
            for n in nodes:
                print(' ', nname, n.text.decode())
