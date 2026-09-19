# Contributing rules to megasast

Rules live in `src/megasast/rules/<language>_rules.py` as
`Rule(id, name, description, severity, languages, queries, message)` with
optional `remediation`, `tags`, `cwe`, and `owasp` fields. Append the new
rule to the file's `RULES` list; `registry.py` picks it up automatically
(including third-party `megasast.rules` entry points).

Every new rule must:

1. **Add a README table row and regenerate RULES.md** — enforced by
   `tests/test_readme_rules.py`. Keep the `ID | Severity | Languages | Name`
   format in the README; run `python scripts/generate_rules_md.py` so the
   detailed catalog (description, CWE/OWASP, remediation) stays in sync.
2. **Add positive and negative cases** to `tests/test_rule_coverage.py`:
   one snippet that must fire exactly once, and benign look-alikes that
   must not fire (e.g. `shell=False`, `verify=True`, a plain string for a
   secret rule).
3. **Run the suite**: `python -m pytest tests -q`.

## Writing queries

- A query may contain several patterns separated by `;`; the engine
  compiles and runs each part separately. Every reported node must be
  captured as `@match` (conventionally the outermost node, so the finding
  location covers the whole expression).
- Supported predicates are `#eq?` (exact text) and `#match?` (regex
  search). Check the actual node/field names against the real grammar
  before shipping — names differ per language and grammar version
  (`arguments` vs `argument_list`, `encapsed_string` vs `string`,
  `keyed_element` vs `field`, ...). Dump the tree first:

  ```python
  from tree_sitter import Parser
  from tree_sitter_language_pack import get_language
  lang = get_language("php")  # python, javascript, typescript, java, c, go, rust
  tree = Parser(lang).parse(b'<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); ?>')
  print(tree.root_node.sexp())
  ```

  Then verify the pattern compiles and matches (and rejects the negative
  case) with `tree_sitter.Query` + `QueryCursor` before wiring it into a
  rule.

### Predicates on single-capture patterns are silently ignored (important)

Tree-sitter ignores filtering predicates (`#eq?`, `#match?`, ...) on
patterns that capture only a single root node, turning the rule into a
match-everything rule with no error. This:

```python
# BROKEN — matches every string literal
"(string_literal) @match (#match? @match \"AKIA[0-9A-Z]{16}\")"
```

must instead predicate on a non-root (inner) capture:

```python
# CORRECT — predicate on the inner content node
"(string_literal (string_content) @s (#match? @s \"AKIA[0-9A-Z]{16}\")) @match"
```

`registry.py` prints a stderr warning for this shape at load time, and
`tests/test_query_guard.py::test_no_builtin_rule_has_ineffective_predicates`
fails the suite if any registered rule has one. The negative test in (2)
is still required: it is what catches over-broad queries end to end.

## Out of scope for AST rules

Shallow tree-sitter patterns cannot do taint tracking or framework
modeling, so do not add rules for: CSRF, missing/broken authorization,
SSRF, IDOR, use-after-free / out-of-bounds (needs dataflow), or anything
requiring "user input reaches X" reasoning. Prefer high-precision,
review-grade heuristics and say so in the description when a rule is one
(e.g. SQL-string rules).
