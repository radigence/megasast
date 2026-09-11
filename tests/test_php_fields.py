from tree_sitter_language_pack import get_language
from tree_sitter import Parser

lang = get_language('php')
p = Parser(lang)
t = p.parse(b'<?php eval("x"); ?>')
root = t.root_node

def find(node):
    if node.type == 'function_call_expression':
        print('node:', node)
        print('children:', [(c.type, c.text.decode()) for c in node.children])
        print('named_children:', [(c.type, c.text.decode()) for c in node.named_children])
        # Try field access
        for i in range(node.child_count):
            child = node.child(i)
            print(' child', i, child.type, child.text.decode())
        print('field name:', node.child_by_field_name('name'))
    for c in node.children:
        find(c)

find(root)
