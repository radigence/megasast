from tree_sitter_language_pack import get_language
from tree_sitter import Parser

lang = get_language('php')
parser = Parser(lang)
code = b'<?php eval("x"); exec("ls"); shell_exec("id"); unserialize($d); ?>'
tree = parser.parse(code)
root = tree.root_node

def dump(node, indent=0):
    txt = node.text.decode(errors='replace')
    if len(txt) > 60:
        txt = txt[:57] + '...'
    print('  '*indent, node.type, repr(txt))
    for c in node.children:
        dump(c, indent+1)

dump(root)
print('\n--- sexp ---')
print(root.sexp())
