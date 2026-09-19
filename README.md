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

Full per-rule reference with descriptions and remediation guidance: [RULES.md](RULES.md).

| ID | Severity | Languages | Name |
| --- | --- | --- | --- |
| `megasast/py-eval` | HIGH | python | Python eval() usage |
| `megasast/py-exec` | HIGH | python | Python exec() usage |
| `megasast/py-os-system` | HIGH | python | Python os.system() usage |
| `megasast/py-pickle-load` | HIGH | python | Python pickle.load() usage |
| `megasast/py-pickle-loads` | HIGH | python | Python pickle.loads() usage |
| `megasast/py-marshal-load` | HIGH | python | Python marshal.load()/loads() usage |
| `megasast/py-yaml-load` | MEDIUM | python | Python yaml.load() usage |
| `megasast/py-subprocess-shell` | HIGH | python | Python subprocess with shell=True |
| `megasast/py-asyncio-subprocess-shell` | HIGH | python | Python asyncio.create_subprocess_shell() usage |
| `megasast/py-requests-no-verify` | HIGH | python | Python requests call with verify=False |
| `megasast/py-ssl-unverified-context` | HIGH | python | Python unverified SSL context |
| `megasast/py-hashlib-md5` | MEDIUM | python | Python MD5 usage |
| `megasast/py-hashlib-sha1` | MEDIUM | python | Python SHA-1 usage |
| `megasast/py-mktemp` | MEDIUM | python | Python tempfile.mktemp() usage |
| `megasast/py-os-mktemp` | MEDIUM | python | Python os.mktemp() usage |
| `megasast/py-chmod-777` | MEDIUM | python | Python os.chmod() with 0o777 |
| `megasast/py-plaintext-protocol` | MEDIUM | python | Python plaintext protocol import |
| `megasast/py-simple-http-server` | MEDIUM | python | Python SimpleHTTPRequestHandler usage |
| `megasast/py-jinja2-autoescape` | MEDIUM | python | Python Jinja2 autoescape=False |
| `megasast/py-django-mark-safe` | MEDIUM | python | Python Django mark_safe() usage |
| `megasast/py-sql-fstring` | MEDIUM | python | Python SQL query built with string formatting |
| `megasast/py-flask-debug` | MEDIUM | python | Python Flask debug mode |
| `megasast/js-eval` | HIGH | javascript, typescript | JavaScript eval() usage |
| `megasast/js-new-function` | HIGH | javascript, typescript | JavaScript new Function() usage |
| `megasast/js-innerhtml` | MEDIUM | javascript, typescript | Assignment to innerHTML |
| `megasast/js-outerhtml` | MEDIUM | javascript, typescript | Assignment to outerHTML |
| `megasast/js-insert-adjacent-html` | MEDIUM | javascript, typescript | JavaScript insertAdjacentHTML usage |
| `megasast/js-localstorage-secret` | MEDIUM | javascript, typescript | JavaScript secret stored in web storage |
| `megasast/js-crypto-weak-hash` | MEDIUM | javascript, typescript | JavaScript crypto.createHash with weak algorithm |
| `megasast/js-settimeout-string` | MEDIUM | javascript, typescript | JavaScript setTimeout/setInterval with string |
| `megasast/js-child-process-exec` | HIGH | javascript, typescript | JavaScript child_process.exec usage |
| `megasast/js-child-process-exec-sync` | HIGH | javascript, typescript | JavaScript child_process.execSync usage |
| `megasast/js-vm-runincontext` | HIGH | javascript, typescript | JavaScript vm.runIn*() usage |
| `megasast/js-spawn-shell` | HIGH | javascript, typescript | JavaScript child_process.spawn with shell:true |
| `megasast/js-reject-unauthorized` | HIGH | javascript, typescript | JavaScript rejectUnauthorized:false usage |
| `megasast/js-document-write` | MEDIUM | javascript, typescript | JavaScript document.write usage |
| `megasast/java-runtime-exec` | HIGH | java | Java Runtime.exec() usage |
| `megasast/java-processbuilder` | HIGH | java | Java ProcessBuilder usage |
| `megasast/java-readobject` | HIGH | java | Java deserialization via readObject() |
| `megasast/java-scriptengine-eval` | HIGH | java | Java ScriptEngine.eval() usage |
| `megasast/java-cipher-weak` | MEDIUM | java | Java Cipher with weak algorithm |
| `megasast/java-signature-weak` | MEDIUM | java | Java Signature with weak digest |
| `megasast/java-sql-concat` | MEDIUM | java | Java SQL query built with concatenation |
| `megasast/java-xxe` | MEDIUM | java | Java TransformerFactory usage |
| `megasast/java-jndi-lookup` | MEDIUM | java | Java JNDI lookup usage |
| `megasast/java-message-digest-md5` | MEDIUM | java | Java MessageDigest MD5 usage |
| `megasast/java-message-digest-sha1` | MEDIUM | java | Java MessageDigest SHA-1 usage |
| `megasast/java-ssl-protocol` | LOW | java | Java SSLContext with legacy SSL protocol |
| `megasast/c-system` | HIGH | c, cpp | C system() usage |
| `megasast/c-popen` | HIGH | c, cpp | C popen() usage |
| `megasast/c-strcpy` | MEDIUM | c, cpp | C strcpy() usage |
| `megasast/c-gets` | MEDIUM | c, cpp | C gets() usage |
| `megasast/c-sprintf` | MEDIUM | c, cpp | C sprintf() usage |
| `megasast/c-strcat` | MEDIUM | c, cpp | C strcat() usage |
| `megasast/c-scanf-s` | MEDIUM | c, cpp | C scanf() with %s format |
| `megasast/c-memcpy` | MEDIUM | c, cpp | C memcpy() usage |
| `megasast/c-openssl-weak-hash` | MEDIUM | c, cpp | C OpenSSL MD5/SHA-1 usage |
| `megasast/c-weak-cipher` | MEDIUM | c, cpp | C DES/RC4 usage |
| `megasast/c-mktemp` | MEDIUM | c, cpp | C mktemp() usage |
| `megasast/c-setuid` | MEDIUM | c, cpp | C setuid()/seteuid() usage |
| `megasast/c-chmod-777` | MEDIUM | c, cpp | C chmod() with 0777 |
| `megasast/c-getwd` | LOW | c, cpp | C getwd() usage |
| `megasast/c-strtok` | LOW | c, cpp | C strtok() usage |
| `megasast/c-atoi` | LOW | c, cpp | C atoi()/atol()/atof() usage |
| `megasast/go-exec-cmd` | HIGH | go | Go exec.Command usage |
| `megasast/go-exec-shell` | MEDIUM | go | Go exec.Command with shell |
| `megasast/go-insecure-skip-verify` | HIGH | go | Go InsecureSkipVerify usage |
| `megasast/go-gob-decode` | MEDIUM | go | Go gob decoding usage |
| `megasast/go-sql-sprintf` | MEDIUM | go | Go SQL query built with fmt.Sprintf |
| `megasast/go-crypto-md5` | MEDIUM | go | Go crypto MD5 usage |
| `megasast/go-crypto-sha1` | MEDIUM | go | Go crypto SHA-1 usage |
| `megasast/go-weak-cipher-import` | MEDIUM | go | Go weak cipher import |
| `megasast/go-unsafe-import` | MEDIUM | go | Go unsafe import |
| `megasast/php-eval` | HIGH | php | PHP eval() usage |
| `megasast/php-exec` | HIGH | php | PHP exec() usage |
| `megasast/php-system` | HIGH | php | PHP system() usage |
| `megasast/php-passthru` | HIGH | php | PHP passthru() usage |
| `megasast/php-proc-open` | HIGH | php | PHP proc_open() usage |
| `megasast/php-popen` | HIGH | php | PHP popen() usage |
| `megasast/php-shell-exec` | HIGH | php | PHP shell_exec() usage |
| `megasast/php-assert` | HIGH | php | PHP assert() with string usage |
| `megasast/php-create-function` | HIGH | php | PHP create_function() usage |
| `megasast/php-preg-replace-e` | HIGH | php | PHP preg_replace() with /e modifier |
| `megasast/php-include-variable` | MEDIUM | php | PHP include/require with variable |
| `megasast/php-request-superglobal` | MEDIUM | php | PHP $_REQUEST usage |
| `megasast/php-unserialize` | HIGH | php | PHP unserialize() usage |
| `megasast/php-curl-no-verify` | HIGH | php | PHP curl with disabled TLS verification |
| `megasast/php-sql-concat` | MEDIUM | php | PHP SQL query built with concatenation |
| `megasast/php-mcrypt` | MEDIUM | php | PHP mcrypt_* usage |
| `megasast/php-md5` | MEDIUM | php | PHP md5() usage |
| `megasast/php-sha1` | MEDIUM | php | PHP sha1() usage |
| `megasast/php-extract` | LOW | php | PHP extract() usage |
| `megasast/rust-command` | HIGH | rust | Rust std::process::Command usage |
| `megasast/rust-danger-accept-invalid` | HIGH | rust | Rust danger_accept_invalid_certs/hostnames usage |
| `megasast/rust-unsafe` | LOW | rust | Rust unsafe block usage |
| `megasast/rust-transmute` | MEDIUM | rust | Rust mem::transmute usage |
| `megasast/rust-from-utf8-unchecked` | MEDIUM | rust | Rust String::from_utf8_unchecked usage |
| `megasast/rust-mem-zeroed` | MEDIUM | rust | Rust mem::zeroed usage |
| `megasast/rust-slice-raw-parts` | MEDIUM | rust | Rust from_raw_parts usage |
| `megasast/rust-weak-hash-import` | MEDIUM | rust | Rust md5/sha1 crate usage |
| `megasast/aws-access-key` | HIGH | python, javascript, typescript, java, c, cpp, go, php, rust | Hardcoded AWS access key ID |
| `megasast/hardcoded-secret` | MEDIUM | python, javascript, typescript, java, c, cpp, go, php, rust | Hardcoded secret in source |
| `megasast/insecure-rand` | MEDIUM | python, javascript, typescript, java, c, cpp, go, php | Predictable random number generator |

## Adding rules
Edit `src/megasast/rules/*.py` with `Rule(id, name, description, severity, languages, queries, message)`.
Optional `cwe` and `owasp` fields (e.g. `"CWE-78"`, `"A03:2021 Injection"`) are surfaced in the SARIF rule properties.
A query may contain multiple patterns separated by `;`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for query-authoring rules (including a
silent tree-sitter predicate pitfall), test conventions, and what is out of scope.
