from tree_sitter_language_pack import get_language
from tree_sitter import Parser

lang = get_language('go')
parser = Parser(lang)
code = 'cmd := exec.Command("sh")'
tree = parser.parse(code.encode())
root = tree.root_node

def find_selector(node):
    if node.type == 'selector_expression':
        print('found selector')
        print('children:', [(c.type, c.text.decode()) for c in node.children])
        print('named_children:', [(c.type, c.text.decode()) for c in node.named_children])
        print('fields:', node.fields)
    for c in node.children:
        find_selector(c)

find_selector(root)
