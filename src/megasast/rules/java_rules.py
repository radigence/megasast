from megasast.rules.base import Rule

JAVA_RUNTIME_EXEC = Rule(
    id="megasast/java-runtime-exec",
    name="Java Runtime.exec() usage",
    description="Runtime.exec() can lead to command injection.",
    severity="HIGH",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (method_invocation object: (identifier) @runtime name: (identifier) @factory) name: (identifier) @method (#eq? @runtime \"Runtime\") (#eq? @factory \"getRuntime\") (#eq? @method \"exec\")) @match",
    },
    message="Use of Runtime.exec() — command injection risk.",
    remediation="Use ProcessBuilder with a fixed executable and separate arguments; validate untrusted input before execution.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

JAVA_MESSAGE_DIGEST_MD5 = Rule(
    id="megasast/java-message-digest-md5",
    name="Java MessageDigest MD5 usage",
    description="MD5 is cryptographically broken and unsuitable for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @class name: (identifier) @method arguments: (argument_list (string_literal) @algorithm) (#eq? @class \"MessageDigest\") (#eq? @method \"getInstance\") (#eq? @algorithm \"\\\"MD5\\\"\")) @match",
    },
    message="Use of MessageDigest MD5 — weak cryptographic hash.",
    remediation="Use SHA-256 or SHA-3 for integrity checks, or a dedicated password hashing function for passwords.",
    tags=["security", "cryptography", "weak-hash"]
)

JAVA_MESSAGE_DIGEST_SHA1 = Rule(
    id="megasast/java-message-digest-sha1",
    name="Java MessageDigest SHA-1 usage",
    description="SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @class name: (identifier) @method arguments: (argument_list (string_literal) @algorithm) (#eq? @class \"MessageDigest\") (#eq? @method \"getInstance\") (#eq? @algorithm \"\\\"SHA-1\\\"\")) @match",
    },
    message="Use of MessageDigest SHA-1 — weak cryptographic hash.",
    remediation="Use SHA-256 or SHA-3 for integrity checks, or a dedicated password hashing function for passwords.",
    tags=["security", "cryptography", "weak-hash"]
)

RULES = [JAVA_RUNTIME_EXEC, JAVA_MESSAGE_DIGEST_MD5, JAVA_MESSAGE_DIGEST_SHA1]
