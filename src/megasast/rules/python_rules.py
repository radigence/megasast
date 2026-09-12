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
    tags=["security", "injection"]
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
    tags=["security", "injection"]
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
    tags=["security", "command-injection"]
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
    tags=["security", "deserialization"]
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
    tags=["security", "deserialization"]
)

PYTHON_SUBPROCESS_SHELL = Rule(
    id="megasast/py-subprocess-shell",
    name="Python subprocess.Popen with shell=True",
    description="subprocess.Popen with shell=True can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) arguments: (argument_list (keyword_argument name: (identifier) @kw value: (true)) (#eq? @obj \"subprocess\") (#eq? @m \"Popen\") (#eq? @kw \"shell\"))) @match"
    },
    message="Use of subprocess.Popen with shell=True — command injection risk.",
    remediation="Pass shell=False and supply a fixed executable with an argument list; validate any user-controlled arguments.",
    tags=["security", "command-injection"]
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

RULES = [
    PYTHON_EVAL, PYTHON_EXEC, PYTHON_OS_SYSTEM, PYTHON_PICKLE_LOAD,
    PYTHON_YAML_LOAD, PYTHON_SUBPROCESS_SHELL, PYTHON_SSL_UNVERIFIED_CONTEXT,
    PYTHON_HASHLIB_MD5, PYTHON_HASHLIB_SHA1, PYTHON_MKTEMP,
]
