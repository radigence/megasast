"""Single source of truth for the megasast version.

Reads the installed package metadata so `--version` and the SARIF driver
stay in sync with `pyproject.toml`. Falls back for source checkouts that
were never `pip install`ed.
"""
import importlib.metadata as importlib_metadata

try:
    __version__ = importlib_metadata.version("megasast")
except importlib_metadata.PackageNotFoundError:
    # Source tree without an install; keep it obviously unreleased.
    __version__ = "0.0.0.dev0"
