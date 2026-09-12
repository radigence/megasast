# megasast

```text
 __  __ _____ ____    _    ____    _    ____ _____
|  \/  | ____/ ___|  / \  / ___|  / \  / ___|_   _|
| |\/| |  _|| |  _  / _ \ \___ \ / _ \ \___ \ | |
| |  | | |__| |_| |/ ___ \ ___) / ___ \ ___) || |
|_|  |_|_____\____/_/   \_\____/_/   \_\____/ |_|
```

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

## Docker

Build the image from the repository root:

```bash
docker build -t megasast .
```

Run a read-only scan of the current directory and write the SARIF report to `./output/results.sarif`:

```bash
mkdir -p output
docker run --rm \
  -v "$(pwd):/scan-target:ro" \
  -v "$(pwd)/output:/output" \
  megasast scan /scan-target -o /output/results.sarif --format sarif
```

In PowerShell, use `${PWD}` for the mounted paths:

```powershell
New-Item -ItemType Directory -Force output
docker run --rm `
  -v "${PWD}:/scan-target:ro" `
  -v "${PWD}/output:/output" `
  megasast scan /scan-target -o /output/results.sarif --format sarif
```

The included Compose configuration scans `./scan-target` and writes `./output/report.sarif`:

```bash
mkdir -p scan-target output
docker compose up --build
```

The scan target is deliberately mounted read-only. Mount a separate writable output directory whenever you use `--output`.

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

JSON and SARIF results include each rule's description, tags, severity, and remediation guidance. SARIF also places the guidance in the rule `help` field and the result properties for downstream security platforms.

## Adding rules
Edit `src/megasast/rules/*.py` with `Rule(id, name, description, severity, languages, queries, message)`.
