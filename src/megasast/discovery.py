from pathlib import Path
import os
from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern

from megasast.config import SKIP_DIRS, MAX_FILE_SIZE

def is_skipped_dir(name: str) -> bool:
    return name in SKIP_DIRS

def discover(root: Path, respect_gitignore: bool = True) -> list[Path]:
    files = []
    
    # Build gitignore specs for each directory
    gitignore_specs = {}
    if respect_gitignore:
        # Walk once to collect gitignore files
        for dirpath, dirnames, filenames in os.walk(root):
            base = Path(dirpath)
            if ".gitignore" in filenames:
                gitignore_path = base / ".gitignore"
                try:
                    patterns = gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    spec = PathSpec.from_lines(GitWildMatchPattern, patterns)
                    gitignore_specs[str(base)] = spec
                except Exception:
                    pass
            # prune skipped dirs
            dirnames[:] = [d for d in dirnames if not is_skipped_dir(d)]
    else:
        gitignore_specs = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # prune skipped dirs in-place
        dirnames[:] = [d for d in dirnames if not is_skipped_dir(d)]
        base = Path(dirpath)
        rel_base = base.relative_to(root)
        # Find applicable gitignore specs (from this dir and parents)
        specs = []
        current = base
        while True:
            key = str(current)
            if key in gitignore_specs:
                specs.append(gitignore_specs[key])
            if current == root:
                break
            try:
                current = current.parent
            except ValueError:
                break
        for name in filenames:
            path = base / name
            # size cap
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            # gitignore
            if specs:
                rel = str(rel_base / name).replace(os.sep, "/")
                # check each spec from root down
                ignored = False
                for spec in specs:
                    if spec.match_file(rel):
                        ignored = True
                        break
                if ignored:
                    continue
            files.append(path)
    return files
