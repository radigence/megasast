from pathlib import Path
from megasast.parser import TreeSitterParser
from megasast.rules.registry import RULES
from megasast.findings import Finding

def _node_range(node):
    start_point = node.start_point  # (row, col)
    end_point = node.end_point
    return start_point[0] + 1, start_point[1], end_point[0] + 1, end_point[1]

def _is_suppressed(data: bytes, start_line: int, rule_id: str):
    # Simple suppression: check if previous lines contain # megasast:ignore <rule_id>
    # This is a best-effort heuristic; we parse lines up to start_line
    try:
        text = data.decode('utf-8', errors='replace')
        lines = text.splitlines()
        # Check up to 5 lines before the finding
        start = max(0, start_line - 6)
        snippet = '\n'.join(lines[start:start_line])
        # Look for megasast:ignore or megasast:disable
        # Format: # megasast:ignore rule-id
        for line in lines[start:start_line]:
            if 'megasast:ignore' in line or 'megasast:disable' in line:
                if rule_id in line:
                    return True
    except Exception:
        pass
    return False

def scan_file(path: Path, parser: TreeSitterParser, allowed_rules=None, excluded_rules=None, allowed_severities=None):
    result = parser.parse_file(path)
    if result is None:
        return []
    tree, data, lang_name = result
    findings = []
    
    for rule in RULES:
        if lang_name not in rule.languages:
            continue
        if allowed_rules and rule.id not in allowed_rules:
            continue
        if excluded_rules and rule.id in excluded_rules:
            continue
        if allowed_severities and str(rule.severity).lower() not in allowed_severities:
            continue
        queries = rule.queries
        matches = parser.run_queries(tree, lang_name, queries)
        for m in matches:
            node = m["node"]
            # PHP post-filter for function names
            if lang_name == "php":
                try:
                    func_name = node.text.decode("utf-8", errors="replace")
                    if rule.id == "megasast/php-eval" and func_name != "eval":
                        continue
                    if rule.id == "megasast/php-exec" and func_name != "exec":
                        continue
                    if rule.id == "megasast/php-shell-exec" and func_name != "shell_exec":
                        continue
                    if rule.id == "megasast/php-unserialize" and func_name != "unserialize":
                        continue
                except Exception:
                    continue
            start_line, start_col, end_line, end_col = _node_range(node)
            if _is_suppressed(data, start_line, rule.id):
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
