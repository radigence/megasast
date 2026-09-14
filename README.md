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

## Rules

| ID | Severity | Languages | Name |
| --- | --- | --- | --- |
| `megasast/py-eval` | HIGH | python | Python eval() usage |
| `megasast/py-exec` | HIGH | python | Python exec() usage |
| `megasast/py-os-system` | HIGH | python | Python os.system() usage |
| `megasast/py-pickle-load` | HIGH | python | Python pickle.load() usage |
| `megasast/py-yaml-load` | MEDIUM | python | Python yaml.load() usage |
| `megasast/py-subprocess-shell` | HIGH | python | Python subprocess.Popen with shell=True |
| `megasast/py-ssl-unverified-context` | HIGH | python | Python unverified SSL context |
| `megasast/py-hashlib-md5` | MEDIUM | python | Python MD5 usage |
| `megasast/py-hashlib-sha1` | MEDIUM | python | Python SHA-1 usage |
| `megasast/py-mktemp` | MEDIUM | python | Python tempfile.mktemp() usage |
| `megasast/js-eval` | HIGH | javascript, typescript | JavaScript eval() usage |
| `megasast/js-new-function` | HIGH | javascript, typescript | JavaScript new Function() usage |
| `megasast/js-innerhtml` | MEDIUM | javascript, typescript | Assignment to innerHTML |
| `megasast/js-child-process-exec` | HIGH | javascript, typescript | JavaScript child_process.exec usage |
| `megasast/js-child-process-exec-sync` | HIGH | javascript, typescript | JavaScript child_process.execSync usage |
| `megasast/js-document-write` | MEDIUM | javascript, typescript | JavaScript document.write usage |
| `megasast/java-runtime-exec` | HIGH | java | Java Runtime.exec() usage |
| `megasast/java-message-digest-md5` | MEDIUM | java | Java MessageDigest MD5 usage |
| `megasast/java-message-digest-sha1` | MEDIUM | java | Java MessageDigest SHA-1 usage |
| `megasast/c-system` | HIGH | c, cpp | C system() usage |
| `megasast/c-strcpy` | MEDIUM | c, cpp | C strcpy() usage |
| `megasast/c-gets` | MEDIUM | c, cpp | C gets() usage |
| `megasast/c-sprintf` | MEDIUM | c, cpp | C sprintf() usage |
| `megasast/c-strcat` | MEDIUM | c, cpp | C strcat() usage |
| `megasast/go-exec-cmd` | HIGH | go | Go exec.Command usage |
| `megasast/go-crypto-md5` | MEDIUM | go | Go crypto MD5 usage |
| `megasast/go-crypto-sha1` | MEDIUM | go | Go crypto SHA-1 usage |
| `megasast/php-eval` | HIGH | php | PHP eval() usage |
| `megasast/php-exec` | HIGH | php | PHP exec() usage |
| `megasast/php-shell-exec` | HIGH | php | PHP shell_exec() usage |
| `megasast/php-unserialize` | HIGH | php | PHP unserialize() usage |
| `megasast/php-md5` | MEDIUM | php | PHP md5() usage |
| `megasast/php-sha1` | MEDIUM | php | PHP sha1() usage |
| `megasast/rust-command` | HIGH | rust | Rust std::process::Command usage |
| `megasast/rust-unsafe` | LOW | rust | Rust unsafe block usage |
| `megasast/rust-transmute` | MEDIUM | rust | Rust mem::transmute usage |

## Adding rules
Edit `src/megasast/rules/*.py` with `Rule(id, name, description, severity, languages, queries, message)`.
Optional `cwe` and `owasp` fields (e.g. `"CWE-78"`, `"A03:2021 Injection"`) are surfaced in the SARIF rule properties.
A query may contain multiple patterns separated by `;`.
