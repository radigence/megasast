from megasast.rules.base import Rule

GO_EXEC_CMD = Rule(
    id="megasast/go-exec-cmd",
    name="Go exec.Command usage",
    description="exec.Command can lead to command injection.",
    severity="HIGH",
    languages=["go"],
    queries={
        "go": "(call_expression function: (selector_expression) @sel (#eq? @sel \"exec.Command\")) @match",
    },
    message="Use of exec.Command — command injection risk.",
    remediation="Use a fixed executable and validated, allow-listed arguments. Do not construct shell commands from untrusted input.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

GO_CRYPTO_MD5 = Rule(
    id="megasast/go-crypto-md5",
    name="Go crypto/md5 import",
    description="MD5 is cryptographically broken and unsuitable for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(import_spec path: (interpreted_string_literal) @path (#eq? @path \"\\\"crypto/md5\\\"\")) @match",
    },
    message="Import of crypto/md5 — weak cryptographic hash.",
    remediation="Use crypto/sha256 or crypto/sha512 for integrity checks, or a dedicated password hashing function.",
    tags=["security", "cryptography", "weak-hash"]
)

GO_CRYPTO_SHA1 = Rule(
    id="megasast/go-crypto-sha1",
    name="Go crypto/sha1 import",
    description="SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(import_spec path: (interpreted_string_literal) @path (#eq? @path \"\\\"crypto/sha1\\\"\")) @match",
    },
    message="Import of crypto/sha1 — weak cryptographic hash.",
    remediation="Use crypto/sha256 or crypto/sha512 for integrity checks, or a dedicated password hashing function.",
    tags=["security", "cryptography", "weak-hash"]
)

RULES = [GO_EXEC_CMD, GO_CRYPTO_MD5, GO_CRYPTO_SHA1]
