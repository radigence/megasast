from tree_sitter_language_pack import get_language
from tree_sitter import Parser

lang = get_language('go')
parser = Parser(lang)
code = '''
package main
import "os/exec"
func main() {
    cmd := exec.Command("sh", "-c", "rm -rf /")
}
'''
tree = parser.parse(code.encode())
root = tree.root_node

def dump(node, indent=0):
    print('  '*indent, node.type, node.text.decode(errors='replace')[:60])
    for c in node.children:
        dump(c, indent+1)
dump(root)
