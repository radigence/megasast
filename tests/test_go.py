from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

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

qstr = '(call_expression function: (selector_expression) @f)'
q = Query(lang, qstr)
cursor = QueryCursor(q)
print('matches')
for pat_idx, captures in cursor.matches(root):
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
