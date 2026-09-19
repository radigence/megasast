from megasast.rules.base import Rule

PYTHON_EVAL = Rule(
    id="megasast/py-eval",
    name="Python eval() usage",
    description="Use of eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (identifier) @func (#eq? @func \"eval\")) @match"
    },
    message="Use of eval() — arbitrary code execution risk.",
    remediation="Avoid eval(). Parse the expected input format or use a strict allow-list of supported operations.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PYTHON_EXEC = Rule(
    id="megasast/py-exec",
    name="Python exec() usage",
    description="Use of exec() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (identifier) @func (#eq? @func \"exec\")) @match"
    },
    message="Use of exec() — arbitrary code execution risk.",
    remediation="Avoid exec(). Replace dynamic code execution with explicit functions or a constrained interpreter.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PYTHON_OS_SYSTEM = Rule(
    id="megasast/py-os-system",
    name="Python os.system() usage",
    description="os.system() can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"os\") (#eq? @m \"system\")) @match"
    },
    message="Use of os.system() — command injection risk.",
    remediation="Use subprocess.run with an argument list and validate untrusted input; do not invoke a shell.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PYTHON_PICKLE_LOAD = Rule(
    id="megasast/py-pickle-load",
    name="Python pickle.load() usage",
    description="pickle.load() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"pickle\") (#eq? @m \"load\")) @match"
    },
    message="Use of pickle.load() — arbitrary code execution risk.",
    remediation="Do not unpickle untrusted data. Prefer a data-only format such as JSON and validate its schema.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

PYTHON_YAML_LOAD = Rule(
    id="megasast/py-yaml-load",
    name="Python yaml.load() usage",
    description="yaml.load() without SafeLoader can lead to arbitrary code execution.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"yaml\") (#eq? @m \"load\")) @match"
    },
    message="Use of yaml.load() — arbitrary code execution risk.",
    remediation="Use yaml.safe_load() for untrusted YAML and validate the resulting data structure.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

PYTHON_SUBPROCESS_SHELL = Rule(
    id="megasast/py-subprocess-shell",
    name="Python subprocess with shell=True",
    description="subprocess with shell=True can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) arguments: (argument_list (keyword_argument name: (identifier) @kw value: (true)) (#eq? @obj \"subprocess\") (#match? @m \"^(Popen|run|call|check_call|check_output|getoutput|getstatusoutput)$\") (#eq? @kw \"shell\"))) @match"
    },
    message="Use of subprocess with shell=True — command injection risk.",
    remediation="Pass shell=False and supply a fixed executable with an argument list; validate any user-controlled arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PYTHON_SSL_UNVERIFIED_CONTEXT = Rule(
    id="megasast/py-ssl-unverified-context",
    name="Python unverified SSL context",
    description="ssl._create_unverified_context() disables TLS certificate verification.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @method) (#eq? @obj \"ssl\") (#eq? @method \"_create_unverified_context\")) @match"
    },
    message="TLS certificate verification is disabled.",
    remediation="Use ssl.create_default_context() and keep certificate and hostname verification enabled.",
    tags=["security", "tls", "certificate-validation"]
)

PYTHON_HASHLIB_MD5 = Rule(
    id="megasast/py-hashlib-md5",
    name="Python MD5 usage",
    description="MD5 is cryptographically broken and unsuitable for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @method) (#eq? @obj \"hashlib\") (#eq? @method \"md5\")) @match"
    },
    message="Use of MD5 — weak cryptographic hash.",
    remediation="Use SHA-256 or SHA-3 for integrity checks, or Argon2/bcrypt/scrypt for password hashing.",
    tags=["security", "cryptography", "weak-hash"]
)

PYTHON_HASHLIB_SHA1 = Rule(
    id="megasast/py-hashlib-sha1",
    name="Python SHA-1 usage",
    description="SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @method) (#eq? @obj \"hashlib\") (#eq? @method \"sha1\")) @match"
    },
    message="Use of SHA-1 — weak cryptographic hash.",
    remediation="Use SHA-256 or SHA-3 for integrity checks, or Argon2/bcrypt/scrypt for password hashing.",
    tags=["security", "cryptography", "weak-hash"]
)

PYTHON_MKTEMP = Rule(
    id="megasast/py-mktemp",
    name="Python tempfile.mktemp() usage",
    description="tempfile.mktemp() is vulnerable to race conditions because it only returns a filename.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @method) (#eq? @obj \"tempfile\") (#eq? @method \"mktemp\")) @match"
    },
    message="Use of tempfile.mktemp() — insecure temporary file creation.",
    remediation="Use tempfile.NamedTemporaryFile(), TemporaryFile(), or mkstemp() to create the file atomically.",
    tags=["security", "race-condition", "temporary-files"]
)

PYTHON_PICKLE_LOADS = Rule(
    id="megasast/py-pickle-loads",
    name="Python pickle.loads() usage",
    description="pickle.loads() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"pickle\") (#eq? @m \"loads\")) @match"
    },
    message="Use of pickle.loads() — arbitrary code execution risk.",
    remediation="Do not unpickle untrusted data. Prefer a data-only format such as JSON and validate its schema.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

PYTHON_MARSHAL_LOAD = Rule(
    id="megasast/py-marshal-load",
    name="Python marshal.load()/loads() usage",
    description="marshal.load()/loads() can lead to arbitrary code execution on untrusted data.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"marshal\") (#match? @m \"^loads?$\")) @match"
    },
    message="Use of marshal.load()/loads() — arbitrary code execution risk.",
    remediation="Do not unmarshal untrusted data. Prefer a data-only format such as JSON and validate its schema.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

PYTHON_ASYNCIO_SUBPROCESS_SHELL = Rule(
    id="megasast/py-asyncio-subprocess-shell",
    name="Python asyncio.create_subprocess_shell() usage",
    description="asyncio.create_subprocess_shell() can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"asyncio\") (#eq? @m \"create_subprocess_shell\")) @match"
    },
    message="Use of asyncio.create_subprocess_shell() — command injection risk.",
    remediation="Use asyncio.create_subprocess_exec with a fixed executable and an argument list; validate any user-controlled arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PYTHON_REQUESTS_NO_VERIFY = Rule(
    id="megasast/py-requests-no-verify",
    name="Python requests call with verify=False",
    description="verify=False disables TLS certificate verification and enables man-in-the-middle attacks.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call arguments: (argument_list (keyword_argument name: (identifier) @kw value: (false)) (#eq? @kw \"verify\"))) @match"
    },
    message="TLS certificate verification is disabled (verify=False).",
    remediation="Keep certificate verification enabled and pin the expected CA bundle where appropriate.",
    tags=["security", "tls", "certificate-validation"],
    cwe="CWE-295",
    owasp="A02:2021 Cryptographic Failures"
)

PYTHON_CHMOD_777 = Rule(
    id="megasast/py-chmod-777",
    name="Python os.chmod() with 0o777",
    description="os.chmod() with 0o777 grants read/write/execute to everyone.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) arguments: (argument_list (integer) @mode) (#eq? @obj \"os\") (#eq? @m \"chmod\") (#eq? @mode \"0o777\")) @match"
    },
    message="Use of os.chmod() with 0o777 — overly broad file permissions.",
    remediation="Grant the minimal permissions required (e.g. 0o600 for secrets, 0o644 for public files).",
    tags=["security", "permissions"],
    cwe="CWE-732",
    owasp="A01:2021 Broken Access Control"
)

PYTHON_OS_MKTEMP = Rule(
    id="megasast/py-os-mktemp",
    name="Python os.mktemp() usage",
    description="os.mktemp() only returns a filename and is vulnerable to symlink race conditions.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"os\") (#eq? @m \"mktemp\")) @match"
    },
    message="Use of os.mktemp() — insecure temporary file creation.",
    remediation="Use tempfile.NamedTemporaryFile(), TemporaryFile(), or mkstemp() to create the file atomically.",
    tags=["security", "race-condition", "temporary-files"],
    cwe="CWE-377"
)

PYTHON_PLAINTEXT_PROTOCOL = Rule(
    id="megasast/py-plaintext-protocol",
    name="Python plaintext protocol import",
    description="telnetlib and ftplib transmit credentials and data without encryption.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(import_statement (dotted_name) @m (#match? @m \"^(telnetlib|ftplib)$\")) @match; (import_from_statement module_name: (dotted_name) @m (#match? @m \"^(telnetlib|ftplib)$\")) @match"
    },
    message="Import of a plaintext protocol module — credentials and data sent unencrypted.",
    remediation="Use an encrypted alternative such as SSH (paramiko/asyncssh) or FTPS/SFTP instead of Telnet/FTP.",
    tags=["security", "cleartext-transmission"],
    cwe="CWE-319",
    owasp="A02:2021 Cryptographic Failures"
)

PYTHON_SIMPLE_HTTP_SERVER = Rule(
    id="megasast/py-simple-http-server",
    name="Python SimpleHTTPRequestHandler usage",
    description="Subclassing SimpleHTTPRequestHandler exposes directory listings and serves files without authentication.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(class_definition superclasses: (argument_list (identifier) @b) (#match? @b \"^(SimpleHTTPRequestHandler|BaseHTTPRequestHandler)$\")) @match"
    },
    message="Subclass of a simple HTTP request handler — unauthenticated file serving risk.",
    remediation="Do not expose the debug file server in production. Serve static content from a hardened web server with authentication.",
    tags=["security", "debug-endpoint"],
    cwe="CWE-548"
)

PYTHON_JINJA2_AUTOESCAPE = Rule(
    id="megasast/py-jinja2-autoescape",
    name="Python Jinja2 autoescape=False",
    description="Disabling Jinja2 autoescaping can lead to cross-site scripting when templates render untrusted data.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call arguments: (argument_list (keyword_argument name: (identifier) @kw value: (false)) (#eq? @kw \"autoescape\"))) @match"
    },
    message="Jinja2 autoescaping is disabled — potential XSS.",
    remediation="Keep autoescaping enabled. Escape manually only with vetted, context-aware escaping.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

PYTHON_DJANGO_MARK_SAFE = Rule(
    id="megasast/py-django-mark-safe",
    name="Python Django mark_safe() usage",
    description="mark_safe() exempts a string from HTML escaping and can lead to cross-site scripting on untrusted data.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: [(identifier) @f (attribute attribute: (identifier) @f)] (#eq? @f \"mark_safe\")) @match"
    },
    message="Use of mark_safe() — potential XSS.",
    remediation="Avoid mark_safe() on untrusted data. Sanitize HTML with a vetted allow-list sanitizer or escape explicitly.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

PYTHON_SQL_FSTRING = Rule(
    id="megasast/py-sql-fstring",
    name="Python SQL query built with string formatting",
    description="Building SQL with f-strings or str.format() can lead to SQL injection. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute attribute: (identifier) @m) arguments: (argument_list (string (interpolation))) (#match? @m \"^(execute|executemany)$\")) @match; (call function: (attribute attribute: (identifier) @m) arguments: (argument_list (call function: (attribute attribute: (identifier) @fmt) (#eq? @fmt \"format\"))) (#match? @m \"^(execute|executemany)$\")) @match"
    },
    message="SQL built with string formatting — potential SQL injection.",
    remediation="Use parameterized queries (placeholders) and never interpolate untrusted input into SQL text.",
    tags=["security", "sqli"],
    cwe="CWE-89",
    owasp="A03:2021 Injection"
)

PYTHON_FLASK_DEBUG = Rule(
    id="megasast/py-flask-debug",
    name="Python Flask debug mode",
    description="Running a Flask/Werkzeug app with debug=True exposes an interactive debugger that allows remote code execution.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) arguments: (argument_list (keyword_argument name: (identifier) @kw value: (true))) (#match? @obj \"^(app|application)$\") (#eq? @m \"run\") (#eq? @kw \"debug\")) @match"
    },
    message="Flask app started with debug=True — remote code execution risk.",
    remediation="Never enable debug mode in production. Control it via environment configuration with a safe default.",
    tags=["security", "debug-endpoint"],
    cwe="CWE-489",
    owasp="A05:2021 Security Misconfiguration"
)

RULES = [
    PYTHON_EVAL, PYTHON_EXEC, PYTHON_OS_SYSTEM, PYTHON_PICKLE_LOAD,
    PYTHON_PICKLE_LOADS, PYTHON_MARSHAL_LOAD,
    PYTHON_YAML_LOAD, PYTHON_SUBPROCESS_SHELL, PYTHON_ASYNCIO_SUBPROCESS_SHELL,
    PYTHON_REQUESTS_NO_VERIFY, PYTHON_SSL_UNVERIFIED_CONTEXT,
    PYTHON_HASHLIB_MD5, PYTHON_HASHLIB_SHA1, PYTHON_MKTEMP, PYTHON_OS_MKTEMP,
    PYTHON_CHMOD_777, PYTHON_PLAINTEXT_PROTOCOL, PYTHON_SIMPLE_HTTP_SERVER,
    PYTHON_JINJA2_AUTOESCAPE, PYTHON_DJANGO_MARK_SAFE, PYTHON_SQL_FSTRING,
    PYTHON_FLASK_DEBUG,
]
