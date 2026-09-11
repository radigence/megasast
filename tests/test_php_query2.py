from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('php')
p = Parser(lang)
t = p.parse(b'<?php eval("x"); ?>')

qstr = '(function_call_expression (name) @f)'
q = Query(lang, qstr)
c = QueryCursor(q)
matches = list(c.matches(t.root_node))
print('matches', len(matches))
for pat_idx, captures in matches:
    print(captures)
    for name, nodes in captures.items():
        for n in nodes:
            print(name, n.text.decode())
