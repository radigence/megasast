# megasast

Simple SAST tool for large monorepos. Scans files with tree-sitter, runs AST queries, emits valid SARIF 2.1.0.

## Install
```bash
pip install -e .[dev]
```

## Usage
```bash
megasast scan <path> -o report.sarif --format sarif
megasast scan . --format text --fail-on high
megasast rules
```

Flags:
- `--output / -o` output file
- `--format sarif|text|json`
- `--workers N` parallel workers
- `--fail-on high|medium|low` exit non-zero when findings meet threshold
- `--no-gitignore` ignore .gitignore
- `--rule <id>` / `--no-rule <id>` filter rules
- `--severity high medium low` allow-list severities to report
- `--baseline <file.sarif>` show only new findings
- `--version` show version

## Adding rules
Edit `src/megasast/rules/*.py` with `Rule(id, name, description, severity, languages, queries, message)`.
