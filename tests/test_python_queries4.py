from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('python')
parser = Parser(lang)
code = 'os.system("ls")'
tree = parser.parse(code.encode())
root = tree.root_node

# test attribute query
for qstr in [
    '(call function: (attribute) @a)',
    '(attribute object: (identifier) @obj) @a',
    '(attribute object: (identifier) @obj attribute: (identifier) @m) @a',
]:
    try:
        q = Query(lang, qstr)
        cursor = QueryCursor(q)
        matches = list(cursor.matches(root))
        print('OK', qstr, 'matches', len(matches))
        for pat_idx, captures in matches:
            print(' ', captures)
    except Exception as e:
        print('FAIL', qstr, e)
