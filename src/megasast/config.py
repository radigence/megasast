SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "third_party",
}

MAX_FILE_SIZE = 1_000_000  # 1 MB

def load_config(root):
    from pathlib import Path
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib

    root = Path(root).resolve()
    current = root
    config_path = None
    # Use the closest project configuration, allowing scans from subdirectories.
    while True:
        for candidate in (current / "megasast.toml", current / ".megasast.toml"):
            if candidate.is_file():
                config_path = candidate
                break
        if config_path or current.parent == current:
            break
        current = current.parent

    if config_path is None:
        return {}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        return data.get("megasast", {})
    except Exception:
        return {}
