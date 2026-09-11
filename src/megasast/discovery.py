from pathlib import Path
import os
from pathspec.patterns import GitWildMatchPattern

from megasast.config import SKIP_DIRS, MAX_FILE_SIZE

def is_skipped_dir(name: str) -> bool:
    return name in SKIP_DIRS


def _gitignore_patterns(root: Path) -> list[tuple[Path, list[GitWildMatchPattern]]]:
    """Return .gitignore patterns in parent-before-child evaluation order."""
    patterns_by_dir = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not is_skipped_dir(d))
        if ".gitignore" not in filenames:
            continue
        path = Path(dirpath) / ".gitignore"
        try:
            patterns = [
                GitWildMatchPattern(line)
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line and not line.startswith("#")
            ]
        except (OSError, ValueError):
            continue
        patterns_by_dir.append((Path(dirpath), patterns))
    return patterns_by_dir


def _is_gitignored(path: Path, patterns_by_dir: list[tuple[Path, list[GitWildMatchPattern]]]) -> bool:
    """Apply each .gitignore relative to the directory that owns it."""
    ignored = False
    for base, patterns in patterns_by_dir:
        try:
            relative = path.relative_to(base).as_posix()
        except ValueError:
            continue
        for pattern in patterns:
            if pattern.match_file(relative):
                # In pathspec, ordinary ignore patterns have include=True and
                # negated patterns have include=False.
                ignored = bool(pattern.include)
    return ignored


def discover(root: Path, respect_gitignore: bool = True) -> list[Path]:
    files = []
    root = root.resolve()
    patterns_by_dir = _gitignore_patterns(root) if respect_gitignore else []

    for dirpath, dirnames, filenames in os.walk(root):
        # prune skipped dirs in-place
        dirnames[:] = sorted(d for d in dirnames if not is_skipped_dir(d))
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            # size cap
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            if _is_gitignored(path, patterns_by_dir):
                continue
            files.append(path)
    return files
