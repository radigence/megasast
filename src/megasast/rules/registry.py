import sys
import re

from megasast.rules.base import Rule
import importlib.metadata as importlib_metadata

# A filtering predicate such as (#eq? @cap ...) or (#match? @cap ...).
_PREDICATE_RE = re.compile(r"\(#([A-Za-z][A-Za-z0-9_-]*[!?])")
_CAPTURE_RE = re.compile(r"@([A-Za-z_][A-Za-z0-9_\-.]*)")
# Double-quoted query strings (with backslash escapes), stripped before
# scanning so that e.g. "@" inside a regex is not mistaken for a capture.
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')

def _strip_query_strings(pattern: str) -> str:
    return _STRING_RE.sub('""', pattern)

def ineffective_predicate_warnings(rule: Rule):
    """Return warnings for query patterns whose predicates cannot take effect.

    Tree-sitter silently ignores filtering predicates (#eq?, #match?, ...)
    on patterns that capture only a single (root) node, turning the rule
    into a match-everything rule. Predicates must reference a non-root
    capture; keep @match on the outermost node for the finding location.
    """
    warnings = []
    for lang, query in (rule.queries or {}).items():
        # Same ";" multi-pattern split as engine.run_queries.
        for part in (p.strip() for p in query.split(";")):
            if not part:
                continue
            code = _strip_query_strings(part)
            captures = set(_CAPTURE_RE.findall(code))
            filtering = [p for p in _PREDICATE_RE.findall(code) if p.endswith("?")]
            if filtering and len(captures) == 1:
                warnings.append(
                    f"rule {rule.id} ({lang}): single capture '@{next(iter(captures))}' "
                    f"with filtering predicate(s) {filtering} — tree-sitter ignores "
                    f"predicates on single-capture patterns, so this matches everything; "
                    f"predicate on a non-root capture instead"
                )
    return warnings

def _load_builtin_rules():
    from megasast.rules.python_rules import RULES as PYTHON_RULES
    from megasast.rules.js_rules import RULES as JS_RULES
    from megasast.rules.java_rules import RULES as JAVA_RULES
    from megasast.rules.c_rules import RULES as C_RULES
    from megasast.rules.go_rules import RULES as GO_RULES
    from megasast.rules.php_rules import RULES as PHP_RULES
    from megasast.rules.rust_rules import RULES as RUST_RULES
    from megasast.rules.secrets_rules import RULES as SECRETS_RULES
    return PYTHON_RULES + JS_RULES + JAVA_RULES + C_RULES + GO_RULES + PHP_RULES + RUST_RULES + SECRETS_RULES

def _load_entry_point_rules():
    rules = []
    try:
        eps = importlib_metadata.entry_points().select(group="megasast.rules")
    except Exception as e:
        # Fail loud, not silent: hiding plugin errors masks missing rules.
        print(f"Warning: could not enumerate rule entry points: {e}", file=sys.stderr)
        return rules
    for ep in eps:
        try:
            mod = ep.load()
            # expect module to expose RULES list
            if hasattr(mod, "RULES"):
                rules.extend(mod.RULES)
        except Exception as e:
            # A broken plugin must not take down the scanner, but it must be
            # visible to the operator instead of silently vanishing.
            print(f"Warning: failed to load rule plugin {ep.name!r}: {e}", file=sys.stderr)
    return rules

RULES = _load_builtin_rules() + _load_entry_point_rules()

def _warn_on_ineffective_predicates(rules):
    for rule in rules:
        for warning in ineffective_predicate_warnings(rule):
            print(f"Warning: {warning}", file=sys.stderr)

_warn_on_ineffective_predicates(RULES)
