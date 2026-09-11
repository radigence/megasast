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
    import tomllib
    from pathlib import Path
    config_path = None
    # Look for megasast.toml or .megasast.toml in root and parents
    for candidate in [root / "megasast.toml", root / ".megasast.toml"]:
        if candidate.is_file():
            config_path = candidate
            break
    if not config_path:
        return {}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        return data.get("megasast", {})
    except Exception:
        return {}
