from functools import lru_cache
from pathlib import Path
from megasast.parser import TreeSitterParser, comment_nodes
from megasast.rules.registry import RULES
from megasast.findings import Finding

def _node_range(node):
    start_point = node.start_point  # (row, col)
    end_point = node.end_point
    # Tree-sitter columns are zero-based; SARIF columns are one-based.
    return start_point[0] + 1, start_point[1] + 1, end_point[0] + 1, end_point[1] + 1

def _comment_suppresses(text: str, rule_id: str):
    if "megasast:ignore" not in text and "megasast:disable" not in text:
        return False
    return rule_id in text

def _is_suppressed(lines, comments, start_line: int, rule_id: str):
    """Return True when the finding carries a suppression comment.

    Suppression is line-anchored to avoid silencing unrelated findings:

    - a comment on the finding's own line (trailing or leading):
      ``os.system(cmd)  # megasast:ignore megasast/py-os-system``
    - a *dedicated* suppression comment on the immediately preceding line:
      ``// megasast:ignore megasast/rust-unsafe`` alone above the finding.
      "Dedicated" means the comment is the only non-whitespace content of
      its line, so a trailing rule-specific comment cannot leak upward
      onto the next line's finding.

    Two guards keep the token match precise:

    - The comment must be a real comment node of the parsed tree, so a
      string literal like ``"# megasast:ignore ...",`` can never silence an
      unrelated finding. (Every shipped grammar names its comment syntax
      with a node type containing "comment".)
    - A specific suppression applies only to the exact rule id named in
      the comment text.
    """
    # start_line is 1-based; lines and comment rows are 0-based.
    own = start_line - 1
    prev = own - 1
    for row, col, text in comments:
        if not _comment_suppresses(text, rule_id):
            continue
        if row == own:
            return True
        # A suppression comment on the previous line applies to the finding
        # immediately below it only when that line holds nothing but the
        # comment (leading whitespace allowed).
        if row == prev and 0 <= row < len(lines) and lines[row][:col].strip() == "":
            return True
    return False

@lru_cache(maxsize=None)
def _select_rules(allowed_rules, excluded_rules, allowed_severities):
    """Resolved, filtered rule list; computed once per distinct filter set.

    Receives frozensets (or None) so repeated scan_file calls with the same
    selection reuse the cached list instead of re-filtering the registry
    for every file in the scan.
    """
    selected = []
    for rule in RULES:
        if allowed_rules is not None and rule.id not in allowed_rules:
            continue
        if excluded_rules is not None and rule.id in excluded_rules:
            continue
        if allowed_severities is not None and str(rule.severity).lower() not in allowed_severities:
            continue
        selected.append(rule)
    return tuple(selected)

def scan_file(path: Path, parser: TreeSitterParser, allowed_rules=None, excluded_rules=None, allowed_severities=None):
    result = parser.parse_file(path)
    if result is None:
        return []
    pairs, data = result
    findings = []

    # One decode per file (findings + suppression scanning share it) instead
    # of re-decoding for every match.
    text_lines = data.decode("utf-8", errors="replace").splitlines()
    # Real comment nodes across all grammars the file was parsed under;
    # suppression checks are anchored to them.
    comments = []
    for _, tree in pairs:
        comments.extend(comment_nodes(tree))
    rules = _select_rules(
        frozenset(allowed_rules) if allowed_rules else None,
        frozenset(excluded_rules) if excluded_rules else None,
        frozenset(allowed_severities) if allowed_severities else None,
    )
    for rule in rules:
        for lang_name, tree in pairs:
            # Each grammar in the file's mapping is scanned independently
            # (e.g. `.h` under both c and cpp); rules not declared for the
            # grammar are skipped. Exact-range duplicates from overlapping
            # grammars collapse in the deduplication below.
            if not parser.rule_covers(rule, lang_name):
                continue
            matches = parser.run_queries(tree, lang_name, rule.queries)
            for m in matches:
                node = m["node"]
                start_line, start_col, end_line, end_col = _node_range(node)
                if _is_suppressed(text_lines, comments, start_line, rule.id):
                    continue
                snippet = ""
                try:
                    start_byte = node.start_byte
                    end_byte = node.end_byte
                    snippet_bytes = data[start_byte:end_byte]
                    snippet = snippet_bytes.decode("utf-8", errors="replace")
                except Exception:
                    snippet = ""
                findings.append(Finding(
                    rule_id=rule.id,
                    message=rule.message,
                    path=str(path),
                    start_line=start_line,
                    start_column=start_col,
                    end_line=end_line,
                    end_column=end_col,
                    snippet=snippet,
                    severity=rule.severity,
                ))
    # Deduplicate findings by (rule_id, path, start_line, start_col, end_line, end_col)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.rule_id, f.path, f.start_line, f.start_column, f.end_line, f.end_column)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped
