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

GO_INSECURE_SKIP_VERIFY = Rule(
    id="megasast/go-insecure-skip-verify",
    name="Go InsecureSkipVerify usage",
    description="InsecureSkipVerify disables TLS certificate verification and enables man-in-the-middle attacks.",
    severity="HIGH",
    languages=["go"],
    queries={
        "go": "(keyed_element key: (literal_element (identifier) @k) value: (literal_element (true)) (#eq? @k \"InsecureSkipVerify\")) @match",
    },
    message="TLS certificate verification is disabled (InsecureSkipVerify).",
    remediation="Keep certificate verification enabled and configure the expected CA pool where appropriate.",
    tags=["security", "tls", "certificate-validation"],
    cwe="CWE-295",
    owasp="A02:2021 Cryptographic Failures"
)

GO_GOB_DECODE = Rule(
    id="megasast/go-gob-decode",
    name="Go gob decoding usage",
    description="Decoding gob from untrusted sources can lead to arbitrary code execution via malicious types.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(call_expression function: (selector_expression) @sel (#match? @sel \"^gob\\\\.(Decode|NewDecoder)$\")) @match",
    },
    message="Use of gob decoding — insecure deserialization risk.",
    remediation="Do not decode gob from untrusted sources. Prefer a data-only format such as JSON and validate its schema.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

GO_WEAK_CIPHER_IMPORT = Rule(
    id="megasast/go-weak-cipher-import",
    name="Go weak cipher import",
    description="DES and RC4 are broken and must not be used for encryption.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(import_spec path: (interpreted_string_literal) @path (#match? @path \"\\\"crypto/(des|rc4)\\\"\")) @match",
    },
    message="Import of a broken cipher package — confidentiality risk.",
    remediation="Use crypto/aes with GCM or another modern authenticated cipher.",
    tags=["security", "cryptography", "weak-cipher"],
    cwe="CWE-327",
    owasp="A02:2021 Cryptographic Failures"
)

GO_EXEC_SHELL = Rule(
    id="megasast/go-exec-shell",
    name="Go exec.Command with shell",
    description="exec.Command invoking a shell (sh, bash, cmd, powershell) with -c-style input can lead to command injection. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(call_expression function: (selector_expression) @sel arguments: (argument_list (interpreted_string_literal) @prog) (#eq? @sel \"exec.Command\") (#match? @prog \"\\\"(sh|bash|cmd|powershell|pwsh)\\\"\")) @match",
    },
    message="Use of exec.Command with a shell — command injection risk.",
    remediation="Invoke a fixed executable directly with validated, allow-listed arguments instead of going through a shell.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

GO_SQL_SPRINTF = Rule(
    id="megasast/go-sql-sprintf",
    name="Go SQL query built with fmt.Sprintf",
    description="Building SQL with fmt.Sprintf can lead to SQL injection. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(call_expression function: (selector_expression) @sel arguments: (argument_list (call_expression function: (selector_expression) @fmt)) (#match? @sel \"\\\\.(Query|QueryRow|Exec)$\") (#eq? @fmt \"fmt.Sprintf\")) @match",
    },
    message="SQL built with fmt.Sprintf — potential SQL injection.",
    remediation="Use parameterized queries with placeholders and never interpolate untrusted input into SQL text.",
    tags=["security", "sqli"],
    cwe="CWE-89",
    owasp="A03:2021 Injection"
)

GO_UNSAFE_IMPORT = Rule(
    id="megasast/go-unsafe-import",
    name="Go unsafe import",
    description="The unsafe package bypasses Go's type safety and memory safety guarantees.",
    severity="MEDIUM",
    languages=["go"],
    queries={
        "go": "(import_spec path: (interpreted_string_literal) @path (#eq? @path \"\\\"unsafe\\\"\")) @match",
    },
    message="Import of unsafe — memory safety risk.",
    remediation="Avoid unsafe. If unavoidable, isolate its use and document the safety invariants.",
    tags=["security", "unsoundness"],
    cwe="CWE-119",
    owasp="A04:2021 Insecure Design"
)

RULES = [GO_EXEC_CMD, GO_EXEC_SHELL, GO_INSECURE_SKIP_VERIFY, GO_GOB_DECODE, GO_SQL_SPRINTF, GO_CRYPTO_MD5, GO_CRYPTO_SHA1, GO_WEAK_CIPHER_IMPORT, GO_UNSAFE_IMPORT]
