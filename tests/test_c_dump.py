from tree_sitter_language_pack import get_language
from tree_sitter import Parser

lang = get_language('c')
parser = Parser(lang)
code = 'int main(){ system("ls"); strcpy(a,b); }'
tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type)
    for c in node.children:
        dump(c, indent+1)
dump(root)
