from tree_sitter import Parser, Query, QueryCursor
from tree_sitter_language_pack import get_language
from pathlib import Path
from typing import Dict, List, Tuple

from megasast.config import MAX_FILE_SIZE

# Each extension maps to one or more grammars to scan the file under (in
# preference order). Multi-grammar entries are for genuinely ambiguous or
# supersets-of-each-other cases: `.h` headers are scanned under both the C
# and C++ grammars, and engine-level deduplication collapses findings that
# parse identically in both.
LANG_MAP = {
    ".py": ("python",),
    ".pyi": ("python",),
    ".js": ("javascript",),
    ".mjs": ("javascript",),
    ".cjs": ("javascript",),
    ".ts": ("typescript",),
    ".jsx": ("javascript",),
    ".tsx": ("tsx",),
    ".go": ("go",),
    ".rs": ("rust",),
    ".c": ("c",),
    ".h": ("c", "cpp"),
    ".hpp": ("cpp",),
    ".hh": ("cpp",),
    ".hxx": ("cpp",),
    ".cpp": ("cpp",),
    ".cc": ("cpp",),
    ".cxx": ("cpp",),
    ".java": ("java",),
    ".php": ("php",),
    ".html": ("html",),
    ".htm": ("html",),
    ".yml": ("yaml",),
    ".yaml": ("yaml",),
    ".sh": ("bash",),
    ".bash": ("bash",),
    ".rb": ("ruby",),
    ".cs": ("csharp",),
    ".dockerfile": ("dockerfile",),
}

# Entry-point-style files with no useful suffix, matched on the file name.
FILENAME_MAP = {
    "dockerfile": ("dockerfile",),
    ".dockerfile": ("dockerfile",),
}

# tsx files run under the tsx grammar, but every existing typescript rule
# query works unchanged against it (identical node names), so rules that
# declare "typescript" are also applied to tsx files via this alias. This
# avoids tagging every rule's languages list with a literal "tsx" entry.
QUERY_ALIAS = {"tsx": "typescript"}

def _decode_bytes(data: bytes) -> Tuple[bytes, str]:
    # Reject binary files containing null bytes
    if b"\x00" in data:
        return None, "binary"
    try:
        data.decode("utf-8")
        return data, "utf-8"
    except UnicodeDecodeError:
        # Fallback to latin-1 for text files with non-utf8 bytes
        try:
            data.decode("latin-1")
            return data, "latin-1"
        except UnicodeDecodeError:
            return None, "binary"


def comment_nodes(tree) -> list:
    """Return every comment node as (start_row, start_col, text).

    Every shipped grammar names its comment syntax with a node type
    containing "comment" ("comment", "line_comment", ...), which makes this
    a language-agnostic way to find real comment text (and to keep it out
    of reach of string-literal lookalikes). Used by the engine to anchor
    suppression comments.
    """
    nodes = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if "comment" in node.type:
            nodes.append((node.start_point[0], node.start_point[1], node.text.decode("utf-8", errors="replace")))
        stack.extend(node.children)
    nodes.reverse()
    return nodes

class TreeSitterParser:
    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, object] = {}
        # Compiled query cache, keyed on (lang_name, full query string).
        # Query compilation is expensive relative to evaluation; without the
        # cache every rule pattern would be recompiled for every scanned
        # file, which dominates scan time on large repositories. The parser
        # instance is per-process (created once in each pool worker), so the
        # cache is naturally process-local and safe to share across files.
        self._queries: Dict[Tuple[str, str], List[Query]] = {}

    def _compiled_queries(self, lang_name: str, q_str: str) -> List[Query]:
        """Compile each ';'-separated pattern of a rule query, once.

        The tree-sitter binding only evaluates the first pattern of a
        combined query, so compile and run each pattern separately.
        """
        cache_key = (lang_name, q_str)
        compiled = self._queries.get(cache_key)
        if compiled is not None:
            return compiled
        compiled = []
        for pattern in (part.strip() for part in q_str.split(";")):
            if not pattern:
                continue
            try:
                compiled.append(Query(self._languages[lang_name], pattern))
            except Exception as e:
                import sys
                print(f"Warning: query compile error for {lang_name}: {pattern[:80]}... {e}", file=sys.stderr)
        self._queries[cache_key] = compiled
        return compiled

    def _get_parser(self, lang_name: str):
        if lang_name not in self._parsers:
            try:
                lang = get_language(lang_name)
            except Exception:
                return None
            parser = Parser(lang)
            self._parsers[lang_name] = parser
            self._languages[lang_name] = lang
        return self._parsers[lang_name]

    def parse_file(self, path: Path):
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if not data:
            return None
        # Enforce the DoS size bound at the parse boundary itself (defense in
        # depth), not only in discovery.
        if len(data) > MAX_FILE_SIZE:
            return None
        decoded, _ = _decode_bytes(data)
        if decoded is None:
            return None
        ext = path.suffix.lower()
        lang_names = FILENAME_MAP.get(path.name.lower()) or LANG_MAP.get(ext)
        if not lang_names:
            return None
        # A file may be scanned under several grammars (see LANG_MAP); collect
        # every grammar that binds successfully.
        pairs = []
        for lang_name in lang_names:
            parser = self._get_parser(lang_name)
            if parser is None:
                continue
            try:
                tree = parser.parse(data)
            except Exception:
                continue
            pairs.append((lang_name, tree))
        if not pairs:
            return None
        return pairs, data

    def rule_covers(self, rule, lang_name: str) -> bool:
        """True when rule applies to files scanned under lang_name.

        Mirrors QUERY_ALIAS so rules declaring "typescript" also apply to
        files parsed with the tsx grammar.
        """
        if lang_name in rule.languages:
            return True
        alias = QUERY_ALIAS.get(lang_name)
        return alias is not None and alias in rule.languages

    def run_queries(self, tree, lang_name: str, queries: Dict[str, str]) -> List[dict]:
        matches = []
        if not queries:
            return matches
        if lang_name not in self._languages:
            return matches
        q_str = queries.get(lang_name)
        if q_str is None:
            # Alias fallback: a tsx file runs its typescript query set (see
            # QUERY_ALIAS).
            alias = QUERY_ALIAS.get(lang_name)
            if alias is not None:
                q_str = queries.get(alias)
        if q_str is None:
            return matches
        for query in self._compiled_queries(lang_name, q_str):
            cursor = QueryCursor(query)
            for _pattern_idx, captures_dict in cursor.matches(tree.root_node):
                # Rules should capture the expression to report as @match.  Retain a
                # sensible fallback for third-party rules that have exactly one capture.
                nodes = captures_dict.get("match")
                capture_name = "match"
                if nodes is None and len(captures_dict) == 1:
                    capture_name, nodes = next(iter(captures_dict.items()))
                if nodes is None:
                    continue
                for node in nodes:
                    matches.append({"node": node, "capture": capture_name})
        return matches
