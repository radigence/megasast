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
  lang = get_language("php")  # python, tsx, yaml, dockerfile, bash, ruby, csharp, ...
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

## Grammar drift is a real failure, not noise

The `tree-sitter` / `tree-sitter-language-pack` dependencies carry no upper
bound, and the pack regenerates grammars continuously. When a grammar
release changes node names, rule queries stop matching and the testbed
tests fail (each testbed file must fire exactly its documented rules).
That failure is the intentional drift gate: fix it by re-dumping the tree
and updating the affected queries — do not "fix" it by deleting testbed
entries or dropping expected rules from the manifest.

## Third-party rules (plugins)

Rules don't have to live in this repository. A package can expose its own
rules via the `megasast.rules` entry-point group; megasast loads them at
startup (in addition to the built-ins) and surfaces them in the `rules`
subcommand and the SARIF rule list the same way.

Create a package with a module exposing a module-level `RULES` list:

```python
# src/mypkg/rules.py
from megasast.rules.base import Rule

MY_RULE = Rule(
    id="mypkg/my-rule",
    name="My custom rule",
    description="Description of the pattern.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": '(call function: (identifier) @f (#eq? @f "my_invoke")) @match',
    },
    message="My rule fired.",
    remediation="How to fix it.",
    tags=["security"],
)

RULES = [MY_RULE]
```

```toml
# pyproject.toml of the plugin package
[project.entry-points."megasast.rules"]
mypkg = "mypkg.rules"
```

Install both packages, run `megasast rules`, and your rule appears. Query
authoring follows the same conventions as built-in rules — including the
single-capture predicate pitfall above.

## Out of scope for AST rules

Shallow tree-sitter patterns cannot do taint tracking or framework
modeling, so do not add rules for: CSRF, missing/broken authorization,
SSRF, IDOR, use-after-free / out-of-bounds (needs dataflow), or anything
requiring "user input reaches X" reasoning. Prefer high-precision,
review-grade heuristics and say so in the description when a rule is one
(e.g. SQL-string rules).
