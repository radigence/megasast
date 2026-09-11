from tree_sitter_language_pack import get_language
from tree_sitter import Parser, Query, QueryCursor

lang = get_language('php')
p = Parser(lang)
code = b'<?php eval("x"); ?>'
t = p.parse(code)

queries = [
    '(function_call_expression)',
    '(function_call_expression name: (name))',
    '(function_call_expression name: (name) @f)',
]

for qstr in queries:
    try:
        q = Query(lang, qstr)
        c = QueryCursor(q)
        matches = list(c.matches(t.root_node))
        print('OK', qstr, 'matches', len(matches))
        for pat_idx, captures in matches:
            print(' ', captures)
    except Exception as e:
        print('FAIL', qstr, e)
