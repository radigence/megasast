# megasast rule catalog

Full per-rule reference: description, severity, CWE/OWASP mapping,
and remediation guidance. The summary table lives in [README.md](README.md#rules).

## Contents

- [Python (22)](#python)
- [JavaScript / TypeScript (14)](#javascript--typescript)
- [Java (12)](#java)
- [C / C++ (16)](#c--c)
- [Go (9)](#go)
- [PHP (19)](#php)
- [Rust (8)](#rust)
- [Cross-language (3)](#cross-language)

## Python

### `megasast/py-eval` — Python eval() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

Use of eval() can lead to arbitrary code execution.

**Remediation:** Avoid eval(). Parse the expected input format or use a strict allow-list of supported operations.

**Finding message:** Use of eval() — arbitrary code execution risk.


### `megasast/py-exec` — Python exec() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

Use of exec() can lead to arbitrary code execution.

**Remediation:** Avoid exec(). Replace dynamic code execution with explicit functions or a constrained interpreter.

**Finding message:** Use of exec() — arbitrary code execution risk.


### `megasast/py-os-system` — Python os.system() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

os.system() can lead to command injection.

**Remediation:** Use subprocess.run with an argument list and validate untrusted input; do not invoke a shell.

**Finding message:** Use of os.system() — command injection risk.


### `megasast/py-pickle-load` — Python pickle.load() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

pickle.load() can lead to arbitrary code execution.

**Remediation:** Do not unpickle untrusted data. Prefer a data-only format such as JSON and validate its schema.

**Finding message:** Use of pickle.load() — arbitrary code execution risk.


### `megasast/py-pickle-loads` — Python pickle.loads() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

pickle.loads() can lead to arbitrary code execution.

**Remediation:** Do not unpickle untrusted data. Prefer a data-only format such as JSON and validate its schema.

**Finding message:** Use of pickle.loads() — arbitrary code execution risk.


### `megasast/py-marshal-load` — Python marshal.load()/loads() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

marshal.load()/loads() can lead to arbitrary code execution on untrusted data.

**Remediation:** Do not unmarshal untrusted data. Prefer a data-only format such as JSON and validate its schema.

**Finding message:** Use of marshal.load()/loads() — arbitrary code execution risk.


### `megasast/py-yaml-load` — Python yaml.load() usage

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

yaml.load() without SafeLoader can lead to arbitrary code execution.

**Remediation:** Use yaml.safe_load() for untrusted YAML and validate the resulting data structure.

**Finding message:** Use of yaml.load() — arbitrary code execution risk.


### `megasast/py-subprocess-shell` — Python subprocess with shell=True

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

subprocess with shell=True can lead to command injection.

**Remediation:** Pass shell=False and supply a fixed executable with an argument list; validate any user-controlled arguments.

**Finding message:** Use of subprocess with shell=True — command injection risk.


### `megasast/py-asyncio-subprocess-shell` — Python asyncio.create_subprocess_shell() usage

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

asyncio.create_subprocess_shell() can lead to command injection.

**Remediation:** Use asyncio.create_subprocess_exec with a fixed executable and an argument list; validate any user-controlled arguments.

**Finding message:** Use of asyncio.create_subprocess_shell() — command injection risk.


### `megasast/py-requests-no-verify` — Python requests call with verify=False

**Severity:** HIGH · **Languages:** python · **CWE:** CWE-295 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, certificate-validation

verify=False disables TLS certificate verification and enables man-in-the-middle attacks.

**Remediation:** Keep certificate verification enabled and pin the expected CA bundle where appropriate.

**Finding message:** TLS certificate verification is disabled (verify=False).


### `megasast/py-ssl-unverified-context` — Python unverified SSL context

**Severity:** HIGH · **Languages:** python · **Tags:** security, tls, certificate-validation

ssl._create_unverified_context() disables TLS certificate verification.

**Remediation:** Use ssl.create_default_context() and keep certificate and hostname verification enabled.

**Finding message:** TLS certificate verification is disabled.


### `megasast/py-hashlib-md5` — Python MD5 usage

**Severity:** MEDIUM · **Languages:** python · **Tags:** security, cryptography, weak-hash

MD5 is cryptographically broken and unsuitable for security-sensitive hashing.

**Remediation:** Use SHA-256 or SHA-3 for integrity checks, or Argon2/bcrypt/scrypt for password hashing.

**Finding message:** Use of MD5 — weak cryptographic hash.


### `megasast/py-hashlib-sha1` — Python SHA-1 usage

**Severity:** MEDIUM · **Languages:** python · **Tags:** security, cryptography, weak-hash

SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.

**Remediation:** Use SHA-256 or SHA-3 for integrity checks, or Argon2/bcrypt/scrypt for password hashing.

**Finding message:** Use of SHA-1 — weak cryptographic hash.


### `megasast/py-mktemp` — Python tempfile.mktemp() usage

**Severity:** MEDIUM · **Languages:** python · **Tags:** security, race-condition, temporary-files

tempfile.mktemp() is vulnerable to race conditions because it only returns a filename.

**Remediation:** Use tempfile.NamedTemporaryFile(), TemporaryFile(), or mkstemp() to create the file atomically.

**Finding message:** Use of tempfile.mktemp() — insecure temporary file creation.


### `megasast/py-os-mktemp` — Python os.mktemp() usage

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-377 · **Tags:** security, race-condition, temporary-files

os.mktemp() only returns a filename and is vulnerable to symlink race conditions.

**Remediation:** Use tempfile.NamedTemporaryFile(), TemporaryFile(), or mkstemp() to create the file atomically.

**Finding message:** Use of os.mktemp() — insecure temporary file creation.


### `megasast/py-chmod-777` — Python os.chmod() with 0o777

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-732 · **OWASP:** A01:2021 Broken Access Control · **Tags:** security, permissions

os.chmod() with 0o777 grants read/write/execute to everyone.

**Remediation:** Grant the minimal permissions required (e.g. 0o600 for secrets, 0o644 for public files).

**Finding message:** Use of os.chmod() with 0o777 — overly broad file permissions.


### `megasast/py-plaintext-protocol` — Python plaintext protocol import

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-319 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cleartext-transmission

telnetlib and ftplib transmit credentials and data without encryption.

**Remediation:** Use an encrypted alternative such as SSH (paramiko/asyncssh) or FTPS/SFTP instead of Telnet/FTP.

**Finding message:** Import of a plaintext protocol module — credentials and data sent unencrypted.


### `megasast/py-simple-http-server` — Python SimpleHTTPRequestHandler usage

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-548 · **Tags:** security, debug-endpoint

Subclassing SimpleHTTPRequestHandler exposes directory listings and serves files without authentication.

**Remediation:** Do not expose the debug file server in production. Serve static content from a hardened web server with authentication.

**Finding message:** Subclass of a simple HTTP request handler — unauthenticated file serving risk.


### `megasast/py-jinja2-autoescape` — Python Jinja2 autoescape=False

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-79 · **OWASP:** A03:2021 Injection · **Tags:** security, xss

Disabling Jinja2 autoescaping can lead to cross-site scripting when templates render untrusted data.

**Remediation:** Keep autoescaping enabled. Escape manually only with vetted, context-aware escaping.

**Finding message:** Jinja2 autoescaping is disabled — potential XSS.


### `megasast/py-django-mark-safe` — Python Django mark_safe() usage

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-79 · **OWASP:** A03:2021 Injection · **Tags:** security, xss

mark_safe() exempts a string from HTML escaping and can lead to cross-site scripting on untrusted data.

**Remediation:** Avoid mark_safe() on untrusted data. Sanitize HTML with a vetted allow-list sanitizer or escape explicitly.

**Finding message:** Use of mark_safe() — potential XSS.


### `megasast/py-sql-fstring` — Python SQL query built with string formatting

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-89 · **OWASP:** A03:2021 Injection · **Tags:** security, sqli

Building SQL with f-strings or str.format() can lead to SQL injection. Review whether any part is attacker-controlled.

**Remediation:** Use parameterized queries (placeholders) and never interpolate untrusted input into SQL text.

**Finding message:** SQL built with string formatting — potential SQL injection.


### `megasast/py-flask-debug` — Python Flask debug mode

**Severity:** MEDIUM · **Languages:** python · **CWE:** CWE-489 · **OWASP:** A05:2021 Security Misconfiguration · **Tags:** security, debug-endpoint

Running a Flask/Werkzeug app with debug=True exposes an interactive debugger that allows remote code execution.

**Remediation:** Never enable debug mode in production. Control it via environment configuration with a safe default.

**Finding message:** Flask app started with debug=True — remote code execution risk.


## JavaScript / TypeScript

### `megasast/js-eval` — JavaScript eval() usage

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

Use of eval() can lead to arbitrary code execution.

**Remediation:** Avoid eval(). Parse the expected data format and use an allow-list for supported operations.

**Finding message:** Use of eval() — arbitrary code execution risk.


### `megasast/js-new-function` — JavaScript new Function() usage

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

new Function() can lead to arbitrary code execution.

**Remediation:** Avoid dynamic function construction. Use explicit functions or a constrained expression parser.

**Finding message:** Use of new Function() — arbitrary code execution risk.


### `megasast/js-innerhtml` — Assignment to innerHTML

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-79 · **OWASP:** A03:2021 Injection · **Tags:** security, xss

Assigning to innerHTML can lead to XSS.

**Remediation:** Prefer textContent for text. If HTML is required, sanitize it with a vetted allow-list sanitizer before assignment.

**Finding message:** Assignment to innerHTML — potential XSS.


### `megasast/js-outerhtml` — Assignment to outerHTML

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-79 · **OWASP:** A03:2021 Injection · **Tags:** security, xss

Assigning to outerHTML can lead to XSS.

**Remediation:** Prefer textContent for text. If HTML is required, sanitize it with a vetted allow-list sanitizer before assignment.

**Finding message:** Assignment to outerHTML — potential XSS.


### `megasast/js-insert-adjacent-html` — JavaScript insertAdjacentHTML usage

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-79 · **OWASP:** A03:2021 Injection · **Tags:** security, xss

insertAdjacentHTML parses its argument as HTML and can lead to XSS.

**Remediation:** Prefer safe DOM APIs such as textContent or createElement. Sanitize untrusted HTML before insertion.

**Finding message:** Use of insertAdjacentHTML — potential XSS.


### `megasast/js-child-process-exec` — JavaScript child_process.exec usage

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

Direct child_process.exec calls can lead to command injection.

**Remediation:** Prefer execFile or spawn with a fixed executable and argument array; validate untrusted input.

**Finding message:** Use of child_process.exec — command injection risk.


### `megasast/js-child-process-exec-sync` — JavaScript child_process.execSync usage

**Severity:** HIGH · **Languages:** javascript, typescript · **Tags:** security, command-injection

Direct child_process.execSync calls can lead to command injection and block the event loop.

**Remediation:** Prefer execFile or spawn with a fixed executable and argument array; validate untrusted input.

**Finding message:** Use of child_process.execSync — command injection risk.


### `megasast/js-document-write` — JavaScript document.write usage

**Severity:** MEDIUM · **Languages:** javascript, typescript · **Tags:** security, xss

document.write can introduce cross-site scripting when the written content is attacker-controlled.

**Remediation:** Use safe DOM APIs such as textContent or createElement. Sanitize untrusted HTML before insertion.

**Finding message:** Use of document.write — potential XSS.


### `megasast/js-vm-runincontext` — JavaScript vm.runIn*() usage

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

vm.runInNewContext()/runInThisContext()/runInContext() can lead to arbitrary code execution.

**Remediation:** Avoid executing dynamic code. If untrusted code must run, isolate it in a separate process with strict resource limits.

**Finding message:** Use of vm.runIn*() — arbitrary code execution risk.


### `megasast/js-spawn-shell` — JavaScript child_process.spawn with shell:true

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

child_process.spawn with shell:true can lead to command injection.

**Remediation:** Prefer execFile or spawn without shell using a fixed executable and argument array; validate untrusted input.

**Finding message:** Use of child_process.spawn with shell:true — command injection risk.


### `megasast/js-reject-unauthorized` — JavaScript rejectUnauthorized:false usage

**Severity:** HIGH · **Languages:** javascript, typescript · **CWE:** CWE-295 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, certificate-validation

rejectUnauthorized:false disables TLS certificate verification and enables man-in-the-middle attacks.

**Remediation:** Keep certificate verification enabled and configure the expected CA bundle where appropriate.

**Finding message:** TLS certificate verification is disabled (rejectUnauthorized:false).


### `megasast/js-localstorage-secret` — JavaScript secret stored in web storage

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-922 · **Tags:** security, secrets, insecure-storage

Storing tokens or credentials in localStorage/sessionStorage exposes them to any script running on the page.

**Remediation:** Keep tokens in httpOnly, Secure cookies or in memory. Never persist long-lived secrets in web storage.

**Finding message:** Secret stored in web storage — accessible to any page script.


### `megasast/js-crypto-weak-hash` — JavaScript crypto.createHash with weak algorithm

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-328 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-hash

MD5, SHA-1, and MD4 are broken or deprecated for security-sensitive hashing.

**Remediation:** Use SHA-256 or stronger for integrity checks, or a dedicated password hashing function for passwords.

**Finding message:** Weak hash algorithm in crypto.createHash — collision and preimage risk.


### `megasast/js-settimeout-string` — JavaScript setTimeout/setInterval with string

**Severity:** MEDIUM · **Languages:** javascript, typescript · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

Passing a string to setTimeout()/setInterval() evaluates it as code, like eval().

**Remediation:** Pass a function reference instead of a string.

**Finding message:** setTimeout/setInterval with a string — arbitrary code execution risk.


## Java

### `megasast/java-runtime-exec` — Java Runtime.exec() usage

**Severity:** HIGH · **Languages:** java · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

Runtime.exec() can lead to command injection.

**Remediation:** Use ProcessBuilder with a fixed executable and separate arguments; validate untrusted input before execution.

**Finding message:** Use of Runtime.exec() — command injection risk.


### `megasast/java-processbuilder` — Java ProcessBuilder usage

**Severity:** HIGH · **Languages:** java · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

ProcessBuilder can lead to command injection.

**Remediation:** Use a fixed executable with separate, validated arguments; never build the command from untrusted input.

**Finding message:** Use of ProcessBuilder — command injection risk.


### `megasast/java-readobject` — Java deserialization via readObject()

**Severity:** HIGH · **Languages:** java · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

readObject() on ObjectInputStream or XMLDecoder can lead to arbitrary code execution on untrusted data.

**Remediation:** Do not deserialize untrusted data. Prefer a data-only format such as JSON and validate its schema.

**Finding message:** Use of readObject() — insecure deserialization risk.


### `megasast/java-scriptengine-eval` — Java ScriptEngine.eval() usage

**Severity:** HIGH · **Languages:** java · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

ScriptEngine.eval() can lead to arbitrary code execution.

**Remediation:** Avoid evaluating dynamic code. Use an explicit parser or a strict allow-list of supported operations.

**Finding message:** Use of ScriptEngine.eval() — arbitrary code execution risk.


### `megasast/java-cipher-weak` — Java Cipher with weak algorithm

**Severity:** MEDIUM · **Languages:** java · **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-cipher

DES, RC4, and Blowfish are broken or deprecated for encryption.

**Remediation:** Use AES/GCM or another modern authenticated cipher.

**Finding message:** Weak cipher algorithm in Cipher.getInstance — confidentiality risk.


### `megasast/java-signature-weak` — Java Signature with weak digest

**Severity:** MEDIUM · **Languages:** java · **CWE:** CWE-328 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-hash

MD5- and SHA-1-based signatures are vulnerable to collision attacks.

**Remediation:** Use SHA-256 or stronger with RSA/ECDSA.

**Finding message:** Weak digest in Signature.getInstance — signature forgery risk.


### `megasast/java-sql-concat` — Java SQL query built with concatenation

**Severity:** MEDIUM · **Languages:** java · **CWE:** CWE-89 · **OWASP:** A03:2021 Injection · **Tags:** security, sqli

Building SQL with string concatenation can lead to SQL injection. Review whether any part is attacker-controlled.

**Remediation:** Use PreparedStatement with bound parameters and never concatenate untrusted input into SQL text.

**Finding message:** SQL built with string concatenation — potential SQL injection.


### `megasast/java-xxe` — Java TransformerFactory usage

**Severity:** MEDIUM · **Languages:** java · **CWE:** CWE-611 · **OWASP:** A05:2021 Security Misconfiguration · **Tags:** security, xxe

TransformerFactory can resolve external entities and DTDs, enabling XML external entity (XXE) attacks.

**Remediation:** Disable external entities and DTDs (disallow-doctype-decl, external-general-entities=false) or use a hardened parser configuration.

**Finding message:** Use of TransformerFactory — potential XXE.


### `megasast/java-jndi-lookup` — Java JNDI lookup usage

**Severity:** MEDIUM · **Languages:** java · **CWE:** CWE-829 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization, jndi

JNDI lookups on attacker-controlled names can load remote classes and lead to remote code execution.

**Remediation:** Never look up attacker-controlled names. Restrict JNDI to trusted providers and disable remote codebase loading.

**Finding message:** Use of JNDI lookup — remote class loading risk.


### `megasast/java-message-digest-md5` — Java MessageDigest MD5 usage

**Severity:** MEDIUM · **Languages:** java · **Tags:** security, cryptography, weak-hash

MD5 is cryptographically broken and unsuitable for security-sensitive hashing.

**Remediation:** Use SHA-256 or SHA-3 for integrity checks, or a dedicated password hashing function for passwords.

**Finding message:** Use of MessageDigest MD5 — weak cryptographic hash.


### `megasast/java-message-digest-sha1` — Java MessageDigest SHA-1 usage

**Severity:** MEDIUM · **Languages:** java · **Tags:** security, cryptography, weak-hash

SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.

**Remediation:** Use SHA-256 or SHA-3 for integrity checks, or a dedicated password hashing function for passwords.

**Finding message:** Use of MessageDigest SHA-1 — weak cryptographic hash.


### `megasast/java-ssl-protocol` — Java SSLContext with legacy SSL protocol

**Severity:** LOW · **Languages:** java · **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, cryptography

The SSL protocol version is deprecated and vulnerable; TLS must be used instead.

**Remediation:** Request TLSv1.2 or newer explicitly.

**Finding message:** Legacy SSL protocol requested — deprecated and insecure.


## C / C++

### `megasast/c-system` — C system() usage

**Severity:** HIGH · **Languages:** c, cpp · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

system() can lead to command injection.

**Remediation:** Avoid system(). Use execve or a similar API with a fixed executable and validated argument vector.

**Finding message:** Use of system() — command injection risk.


### `megasast/c-popen` — C popen() usage

**Severity:** HIGH · **Languages:** c, cpp · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

popen() can lead to command injection.

**Remediation:** Avoid popen(). Use execve or a similar API with a fixed executable and validated argument vector.

**Finding message:** Use of popen() — command injection risk.


### `megasast/c-strcpy` — C strcpy() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-120 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, buffer-overflow

strcpy() can lead to buffer overflow.

**Remediation:** Use a length-bounded copy and validate destination capacity before copying data.

**Finding message:** Use of strcpy() — buffer overflow risk.


### `megasast/c-gets` — C gets() usage

**Severity:** HIGH · **Languages:** c, cpp · **Tags:** security, buffer-overflow

gets() cannot limit input length and can overflow the destination buffer.

**Remediation:** Use fgets() or another bounded input API and validate the resulting input.

**Finding message:** Use of gets() — buffer overflow risk.


### `megasast/c-sprintf` — C sprintf() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **Tags:** security, buffer-overflow

sprintf() does not know the destination buffer size and can overflow it.

**Remediation:** Use snprintf() with the destination buffer size and check for truncation.

**Finding message:** Use of sprintf() — buffer overflow risk.


### `megasast/c-strcat` — C strcat() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **Tags:** security, buffer-overflow

strcat() can overflow the destination buffer because it does not receive its capacity.

**Remediation:** Use a capacity-aware string builder or verify the destination capacity before concatenation.

**Finding message:** Use of strcat() — buffer overflow risk.


### `megasast/c-scanf-s` — C scanf() with %s format

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-120 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, buffer-overflow

scanf() with %s performs unbounded input and can overflow the destination buffer.

**Remediation:** Use a field width (e.g. %63s) or a bounded input API and validate the result.

**Finding message:** Use of scanf() with %s — buffer overflow risk.


### `megasast/c-memcpy` — C memcpy() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-120 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, buffer-overflow

memcpy() does not check bounds; a wrong length can overflow the destination or read past the source.

**Remediation:** Verify the length against both buffers before copying, or use a bounds-checked alternative.

**Finding message:** Use of memcpy() — buffer overflow risk.


### `megasast/c-openssl-weak-hash` — C OpenSSL MD5/SHA-1 usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-328 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-hash

MD5 and SHA-1 are broken or deprecated for security-sensitive hashing.

**Remediation:** Use SHA-256 or stronger via EVP for integrity checks.

**Finding message:** Use of OpenSSL MD5/SHA-1 — weak cryptographic hash.


### `megasast/c-weak-cipher` — C DES/RC4 usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-cipher

DES and RC4 are broken and must not be used for encryption.

**Remediation:** Use AES/GCM or another modern authenticated cipher via EVP.

**Finding message:** Use of DES/RC4 — broken cipher.


### `megasast/c-mktemp` — C mktemp() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-377 · **Tags:** security, race-condition, temporary-files

mktemp() only returns a filename and is vulnerable to symlink race conditions.

**Remediation:** Use mkstemp() or tmpfile() to create the file atomically.

**Finding message:** Use of mktemp() — insecure temporary file creation.


### `megasast/c-setuid` — C setuid()/seteuid() usage

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-250 · **OWASP:** A01:2021 Broken Access Control · **Tags:** security, privileges

Changing process privileges is error-prone and can leave excessive privileges in reachable code.

**Remediation:** Drop privileges permanently and as early as possible; verify the change succeeded and runs with least privilege.

**Finding message:** Use of setuid()/seteuid() — privilege management risk.


### `megasast/c-chmod-777` — C chmod() with 0777

**Severity:** MEDIUM · **Languages:** c, cpp · **CWE:** CWE-732 · **OWASP:** A01:2021 Broken Access Control · **Tags:** security, permissions

chmod() with 0777 grants read/write/execute to everyone.

**Remediation:** Grant the minimal permissions required.

**Finding message:** Use of chmod() with 0777 — overly broad file permissions.


### `megasast/c-getwd` — C getwd() usage

**Severity:** LOW · **Languages:** c, cpp · **CWE:** CWE-676 · **Tags:** security, buffer-overflow

getwd() does not take a buffer size and can overflow the destination buffer.

**Remediation:** Use getcwd() with an explicit buffer size.

**Finding message:** Use of getwd() — buffer overflow risk.


### `megasast/c-strtok` — C strtok() usage

**Severity:** LOW · **Languages:** c, cpp · **CWE:** CWE-676 · **Tags:** security, buffer-overflow

strtok() modifies its input in place, keeps hidden global state, and is not thread-safe.

**Remediation:** Use strtok_r() or an explicit, bounds-checked parser.

**Finding message:** Use of strtok() — unsafe string tokenization.


### `megasast/c-atoi` — C atoi()/atol()/atof() usage

**Severity:** LOW · **Languages:** c, cpp · **CWE:** CWE-676 · **Tags:** security, input-validation

atoi() and friends perform no error checking; invalid input silently yields 0 and overflow is undefined.

**Remediation:** Use strtol()/strtod() and check errno and the end pointer.

**Finding message:** Use of atoi()/atol()/atof() — unchecked conversion.


## Go

### `megasast/go-exec-cmd` — Go exec.Command usage

**Severity:** HIGH · **Languages:** go · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

exec.Command can lead to command injection.

**Remediation:** Use a fixed executable and validated, allow-listed arguments. Do not construct shell commands from untrusted input.

**Finding message:** Use of exec.Command — command injection risk.


### `megasast/go-exec-shell` — Go exec.Command with shell

**Severity:** MEDIUM · **Languages:** go · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

exec.Command invoking a shell (sh, bash, cmd, powershell) with -c-style input can lead to command injection. Review whether any part is attacker-controlled.

**Remediation:** Invoke a fixed executable directly with validated, allow-listed arguments instead of going through a shell.

**Finding message:** Use of exec.Command with a shell — command injection risk.


### `megasast/go-insecure-skip-verify` — Go InsecureSkipVerify usage

**Severity:** HIGH · **Languages:** go · **CWE:** CWE-295 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, certificate-validation

InsecureSkipVerify disables TLS certificate verification and enables man-in-the-middle attacks.

**Remediation:** Keep certificate verification enabled and configure the expected CA pool where appropriate.

**Finding message:** TLS certificate verification is disabled (InsecureSkipVerify).


### `megasast/go-gob-decode` — Go gob decoding usage

**Severity:** MEDIUM · **Languages:** go · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

Decoding gob from untrusted sources can lead to arbitrary code execution via malicious types.

**Remediation:** Do not decode gob from untrusted sources. Prefer a data-only format such as JSON and validate its schema.

**Finding message:** Use of gob decoding — insecure deserialization risk.


### `megasast/go-sql-sprintf` — Go SQL query built with fmt.Sprintf

**Severity:** MEDIUM · **Languages:** go · **CWE:** CWE-89 · **OWASP:** A03:2021 Injection · **Tags:** security, sqli

Building SQL with fmt.Sprintf can lead to SQL injection. Review whether any part is attacker-controlled.

**Remediation:** Use parameterized queries with placeholders and never interpolate untrusted input into SQL text.

**Finding message:** SQL built with fmt.Sprintf — potential SQL injection.


### `megasast/go-crypto-md5` — Go crypto/md5 import

**Severity:** MEDIUM · **Languages:** go · **Tags:** security, cryptography, weak-hash

MD5 is cryptographically broken and unsuitable for security-sensitive hashing.

**Remediation:** Use crypto/sha256 or crypto/sha512 for integrity checks, or a dedicated password hashing function.

**Finding message:** Import of crypto/md5 — weak cryptographic hash.


### `megasast/go-crypto-sha1` — Go crypto/sha1 import

**Severity:** MEDIUM · **Languages:** go · **Tags:** security, cryptography, weak-hash

SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.

**Remediation:** Use crypto/sha256 or crypto/sha512 for integrity checks, or a dedicated password hashing function.

**Finding message:** Import of crypto/sha1 — weak cryptographic hash.


### `megasast/go-weak-cipher-import` — Go weak cipher import

**Severity:** MEDIUM · **Languages:** go · **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-cipher

DES and RC4 are broken and must not be used for encryption.

**Remediation:** Use crypto/aes with GCM or another modern authenticated cipher.

**Finding message:** Import of a broken cipher package — confidentiality risk.


### `megasast/go-unsafe-import` — Go unsafe import

**Severity:** MEDIUM · **Languages:** go · **CWE:** CWE-119 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, unsoundness

The unsafe package bypasses Go's type safety and memory safety guarantees.

**Remediation:** Avoid unsafe. If unavoidable, isolate its use and document the safety invariants.

**Finding message:** Import of unsafe — memory safety risk.


## PHP

### `megasast/php-eval` — PHP eval() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

eval() can lead to arbitrary code execution.

**Remediation:** Avoid eval(). Use an explicit parser or a strict allow-list of supported operations.

**Finding message:** Use of eval() — arbitrary code execution risk.


### `megasast/php-exec` — PHP exec() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

exec() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of exec() — command injection risk.


### `megasast/php-system` — PHP system() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

system() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of system() — command injection risk.


### `megasast/php-passthru` — PHP passthru() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

passthru() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of passthru() — command injection risk.


### `megasast/php-proc-open` — PHP proc_open() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

proc_open() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of proc_open() — command injection risk.


### `megasast/php-popen` — PHP popen() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

popen() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of popen() — command injection risk.


### `megasast/php-shell-exec` — PHP shell_exec() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

shell_exec() can lead to command injection.

**Remediation:** Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.

**Finding message:** Use of shell_exec() — command injection risk.


### `megasast/php-assert` — PHP assert() with string usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

assert() with a string argument evaluates it as PHP code and can lead to arbitrary code execution.

**Remediation:** Pass a boolean expression to assert() instead of a string. Never assert on attacker-controlled input.

**Finding message:** Use of assert() with a string — arbitrary code execution risk.


### `megasast/php-create-function` — PHP create_function() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

create_function() evaluates its arguments as PHP code and can lead to arbitrary code execution.

**Remediation:** Replace create_function() with an anonymous function (closure).

**Finding message:** Use of create_function() — arbitrary code execution risk.


### `megasast/php-preg-replace-e` — PHP preg_replace() with /e modifier

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

preg_replace() with the /e modifier evaluates the replacement as PHP code and can lead to arbitrary code execution.

**Remediation:** Remove the /e modifier and use preg_replace_callback() instead.

**Finding message:** Use of preg_replace() with /e modifier — arbitrary code execution risk.


### `megasast/php-include-variable` — PHP include/require with variable

**Severity:** MEDIUM · **Languages:** php · **CWE:** CWE-98 · **OWASP:** A03:2021 Injection · **Tags:** security, file-inclusion

Including a file from a variable path can lead to local file inclusion. Review whether any part is attacker-controlled.

**Remediation:** Include only from an allow-list of known files. Never build the path from untrusted input.

**Finding message:** File inclusion from a variable path — local file inclusion risk.


### `megasast/php-request-superglobal` — PHP $_REQUEST usage

**Severity:** MEDIUM · **Languages:** php · **CWE:** CWE-20 · **Tags:** security, input-validation

$_REQUEST merges GET, POST, and COOKIE input, obscuring the data source and weakening validation assumptions.

**Remediation:** Read from $_GET, $_POST, or $_COOKIE explicitly and validate each input.

**Finding message:** Use of $_REQUEST — ambiguous input source.


### `megasast/php-unserialize` — PHP unserialize() usage

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures · **Tags:** security, deserialization

unserialize() can lead to object injection.

**Remediation:** Do not unserialize untrusted data. Prefer JSON and validate the decoded structure.

**Finding message:** Use of unserialize() — object injection risk.


### `megasast/php-curl-no-verify` — PHP curl with disabled TLS verification

**Severity:** HIGH · **Languages:** php · **CWE:** CWE-295 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, certificate-validation

CURLOPT_SSL_VERIFYPEER=false or CURLOPT_SSL_VERIFYHOST=false disables TLS certificate verification and enables man-in-the-middle attacks.

**Remediation:** Keep peer and host verification enabled and configure the expected CA bundle where appropriate.

**Finding message:** TLS certificate verification is disabled (curl SSL verify option set to false).


### `megasast/php-sql-concat` — PHP SQL query built with concatenation

**Severity:** MEDIUM · **Languages:** php · **CWE:** CWE-89 · **OWASP:** A03:2021 Injection · **Tags:** security, sqli

Building SQL with string concatenation can lead to SQL injection. Review whether any part is attacker-controlled.

**Remediation:** Use prepared statements with bound parameters and never concatenate untrusted input into SQL text.

**Finding message:** SQL built with string concatenation — potential SQL injection.


### `megasast/php-mcrypt` — PHP mcrypt_* usage

**Severity:** MEDIUM · **Languages:** php · **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-cipher

mcrypt is deprecated and its ciphers/modes (e.g. ECB, DES) are weak.

**Remediation:** Use openssl_encrypt() with an authenticated mode such as AES-GCM, or sodium.

**Finding message:** Use of mcrypt — deprecated cryptography.


### `megasast/php-md5` — PHP md5() usage

**Severity:** MEDIUM · **Languages:** php · **Tags:** security, cryptography, weak-hash

MD5 is cryptographically broken and unsuitable for security-sensitive hashing.

**Remediation:** Use password_hash() for passwords or SHA-256/SHA-3 for integrity checks.

**Finding message:** Use of md5() — weak cryptographic hash.


### `megasast/php-sha1` — PHP sha1() usage

**Severity:** MEDIUM · **Languages:** php · **Tags:** security, cryptography, weak-hash

SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.

**Remediation:** Use password_hash() for passwords or SHA-256/SHA-3 for integrity checks.

**Finding message:** Use of sha1() — weak cryptographic hash.


### `megasast/php-extract` — PHP extract() usage

**Severity:** LOW · **Languages:** php · **CWE:** CWE-94 · **OWASP:** A03:2021 Injection · **Tags:** security, injection

extract() imports variables into scope and can overwrite trusted variables when run on untrusted data.

**Remediation:** Avoid extract(). Access array entries explicitly instead of importing them into scope.

**Finding message:** Use of extract() — variable pollution risk.


## Rust

### `megasast/rust-command` — Rust std::process::Command usage

**Severity:** HIGH · **Languages:** rust · **CWE:** CWE-78 · **OWASP:** A03:2021 Injection · **Tags:** security, command-injection

std::process::Command can lead to command injection.

**Finding message:** Use of std::process::Command — command injection risk.


### `megasast/rust-danger-accept-invalid` — Rust danger_accept_invalid_certs/hostnames usage

**Severity:** HIGH · **Languages:** rust · **CWE:** CWE-295 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, tls, certificate-validation

danger_accept_invalid_certs()/danger_accept_invalid_hostnames() disables TLS certificate verification and enables man-in-the-middle attacks.

**Remediation:** Keep certificate verification enabled and configure the expected CA roots where appropriate.

**Finding message:** TLS certificate verification is disabled (danger_accept_invalid_*).


### `megasast/rust-unsafe` — Rust unsafe block usage

**Severity:** LOW · **Languages:** rust · **CWE:** CWE-119 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, unsoundness

unsafe blocks bypass Rust's safety guarantees and can lead to undefined behavior.

**Finding message:** Use of an unsafe block — soundness risk.


### `megasast/rust-transmute` — Rust mem::transmute usage

**Severity:** MEDIUM · **Languages:** rust · **CWE:** CWE-119 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, type-punning

mem::transmute can lead to undefined behavior from invalid type punning.

**Finding message:** Use of mem::transmute — undefined behavior risk.


### `megasast/rust-from-utf8-unchecked` — Rust String::from_utf8_unchecked usage

**Severity:** MEDIUM · **Languages:** rust · **CWE:** CWE-704 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, type-confusion

from_utf8_unchecked() skips UTF-8 validation; invalid bytes cause undefined behavior.

**Remediation:** Use String::from_utf8() and handle the error, or validate with std::str::from_utf8() first.

**Finding message:** Use of from_utf8_unchecked() — undefined behavior risk on invalid UTF-8.


### `megasast/rust-mem-zeroed` — Rust mem::zeroed usage

**Severity:** MEDIUM · **Languages:** rust · **CWE:** CWE-704 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, uninitialized-memory

mem::zeroed() is undefined behavior for types with invalid zero values such as bool, references, or NonZero integers.

**Remediation:** Use Default::default(), MaybeUninit, or an explicit valid initializer instead.

**Finding message:** Use of mem::zeroed() — undefined behavior risk for non-zeroable types.


### `megasast/rust-slice-raw-parts` — Rust from_raw_parts usage

**Severity:** MEDIUM · **Languages:** rust · **CWE:** CWE-822 · **OWASP:** A04:2021 Insecure Design · **Tags:** security, buffer-overflow

from_raw_parts() trusts a raw pointer and length; mistakes cause out-of-bounds access and undefined behavior.

**Remediation:** Prefer safe abstractions. If raw parts are required, document and audit the pointer validity, alignment, length, and aliasing invariants.

**Finding message:** Use of from_raw_parts() — out-of-bounds and undefined behavior risk.


### `megasast/rust-weak-hash-import` — Rust md5/sha1 crate usage

**Severity:** MEDIUM · **Languages:** rust · **CWE:** CWE-328 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-hash

The md5 and sha1 crates provide broken or deprecated hashes, unsuitable for security-sensitive hashing.

**Remediation:** Use the sha2 crate (SHA-256 or stronger), or a dedicated password hashing crate for passwords.

**Finding message:** Use of the md5/sha1 crate — weak cryptographic hash.


## Cross-language

### `megasast/aws-access-key` — Hardcoded AWS access key ID

**Severity:** HIGH · **Languages:** python, javascript, typescript, java, c, cpp, go, php, rust · **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures · **Tags:** security, secrets, hardcoded-credentials

A hardcoded AWS access key ID (AKIA...) exposes cloud credentials to anyone with repository access.

**Remediation:** Revoke the exposed key. Load credentials from a secrets manager or environment at runtime, never from source.

**Finding message:** Hardcoded AWS access key ID — credential exposure risk.


### `megasast/hardcoded-secret` — Hardcoded secret in source

**Severity:** MEDIUM · **Languages:** python, javascript, typescript, java, c, cpp, go, php, rust · **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures · **Tags:** security, secrets, hardcoded-credentials

A string literal assigned to a password/secret/token-like variable may expose credentials in source control.

**Remediation:** Move the secret to a secrets manager or environment variable injected at runtime. If it was committed, rotate it.

**Finding message:** Possible hardcoded secret — credential exposure risk.


### `megasast/insecure-rand` — Predictable random number generator

**Severity:** MEDIUM · **Languages:** python, javascript, typescript, java, c, cpp, go, php · **CWE:** CWE-338 · **OWASP:** A02:2021 Cryptographic Failures · **Tags:** security, cryptography, weak-random

Non-cryptographic PRNGs (random, Math.random, rand, math/rand) are predictable and unsuitable for tokens, salts, or session identifiers.

**Remediation:** Use a cryptographic RNG: secrets (Python), crypto.getRandomValues (JS), SecureRandom (Java), getrandom/CSPRNG (C), crypto/rand (Go), random_bytes/random_int (PHP).

**Finding message:** Use of a predictable PRNG — unsuitable for security purposes.
