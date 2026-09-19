from tree_sitter import Parser, Query, QueryCursor
from tree_sitter_language_pack import get_language
from pathlib import Path
from typing import Dict, List, Tuple

from megasast.config import MAX_FILE_SIZE

LANG_MAP = {
    ".py": ("python",),
    ".js": ("javascript",),
    ".ts": ("typescript",),
    ".jsx": ("javascript",),
    ".tsx": ("typescript",),
    ".go": ("go",),
    ".rs": ("rust",),
    ".c": ("c",),
    ".h": ("c",),
    ".cpp": ("cpp",),
    ".cc": ("cpp",),
    ".cxx": ("cpp",),
    ".java": ("java",),
    ".php": ("php",),
}

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

class TreeSitterParser:
    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, object] = {}

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
        lang_names = LANG_MAP.get(ext)
        if not lang_names:
            return None
        lang_name = lang_names[0]
        parser = self._get_parser(lang_name)
        if parser is None:
            return None
        try:
            tree = parser.parse(data)
        except Exception:
            return None
        return tree, data, lang_name

    def run_queries(self, tree, lang_name: str, queries: Dict[str, str]) -> List[dict]:
        matches = []
        if not queries:
            return matches
        try:
            lang = self._languages[lang_name]
        except KeyError:
            return matches
        q_str = queries.get(lang_name)
        if q_str is None:
            return matches
        # A rule query may contain several patterns separated by ';'.
        # The tree-sitter binding only evaluates the first pattern of a
        # combined query, so compile and run each pattern separately.
        for pattern in (part.strip() for part in q_str.split(";")):
            if not pattern:
                continue
            try:
                query = Query(lang, pattern)
            except Exception as e:
                import sys
                print(f"Warning: query compile error for {lang_name}: {pattern[:80]}... {e}", file=sys.stderr)
                continue

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
