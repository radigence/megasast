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

JAVA_READOBJECT = Rule(
    id="megasast/java-readobject",
    name="Java deserialization via readObject()",
    description="readObject() on ObjectInputStream or XMLDecoder can lead to arbitrary code execution on untrusted data.",
    severity="HIGH",
    languages=["java"],
    queries={
        "java": "(method_invocation name: (identifier) @m (#eq? @m \"readObject\")) @match",
    },
    message="Use of readObject() — insecure deserialization risk.",
    remediation="Do not deserialize untrusted data. Prefer a data-only format such as JSON and validate its schema.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

JAVA_SCRIPTENGINE_EVAL = Rule(
    id="megasast/java-scriptengine-eval",
    name="Java ScriptEngine.eval() usage",
    description="ScriptEngine.eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["java"],
    queries={
        "java": "(method_invocation name: (identifier) @m (#eq? @m \"eval\")) @match",
    },
    message="Use of ScriptEngine.eval() — arbitrary code execution risk.",
    remediation="Avoid evaluating dynamic code. Use an explicit parser or a strict allow-list of supported operations.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

JAVA_PROCESSBUILDER = Rule(
    id="megasast/java-processbuilder",
    name="Java ProcessBuilder usage",
    description="ProcessBuilder can lead to command injection.",
    severity="HIGH",
    languages=["java"],
    queries={
        "java": "(object_creation_expression type: (type_identifier) @t (#eq? @t \"ProcessBuilder\")) @match",
    },
    message="Use of ProcessBuilder — command injection risk.",
    remediation="Use a fixed executable with separate, validated arguments; never build the command from untrusted input.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

JAVA_CIPHER_WEAK = Rule(
    id="megasast/java-cipher-weak",
    name="Java Cipher with weak algorithm",
    description="DES, RC4, and Blowfish are broken or deprecated for encryption.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @c name: (identifier) @m arguments: (argument_list (string_literal) @a) (#eq? @c \"Cipher\") (#eq? @m \"getInstance\") (#match? @a \"\\\"(DES|RC4|Blowfish)\")) @match",
    },
    message="Weak cipher algorithm in Cipher.getInstance — confidentiality risk.",
    remediation="Use AES/GCM or another modern authenticated cipher.",
    tags=["security", "cryptography", "weak-cipher"],
    cwe="CWE-327",
    owasp="A02:2021 Cryptographic Failures"
)

JAVA_SIGNATURE_WEAK = Rule(
    id="megasast/java-signature-weak",
    name="Java Signature with weak digest",
    description="MD5- and SHA-1-based signatures are vulnerable to collision attacks.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @c name: (identifier) @m arguments: (argument_list (string_literal) @a) (#eq? @c \"Signature\") (#eq? @m \"getInstance\") (#match? @a \"\\\"(MD5|SHA-?1)\")) @match",
    },
    message="Weak digest in Signature.getInstance — signature forgery risk.",
    remediation="Use SHA-256 or stronger with RSA/ECDSA.",
    tags=["security", "cryptography", "weak-hash"],
    cwe="CWE-328",
    owasp="A02:2021 Cryptographic Failures"
)

JAVA_SQL_CONCAT = Rule(
    id="megasast/java-sql-concat",
    name="Java SQL query built with concatenation",
    description="Building SQL with string concatenation can lead to SQL injection. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation name: (identifier) @m arguments: (argument_list (binary_expression)) (#match? @m \"^(executeQuery|executeUpdate|execute)$\")) @match",
    },
    message="SQL built with string concatenation — potential SQL injection.",
    remediation="Use PreparedStatement with bound parameters and never concatenate untrusted input into SQL text.",
    tags=["security", "sqli"],
    cwe="CWE-89",
    owasp="A03:2021 Injection"
)

JAVA_XXE = Rule(
    id="megasast/java-xxe",
    name="Java TransformerFactory usage",
    description="TransformerFactory can resolve external entities and DTDs, enabling XML external entity (XXE) attacks.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @t name: (identifier) @m (#eq? @t \"TransformerFactory\") (#eq? @m \"newInstance\")) @match",
    },
    message="Use of TransformerFactory — potential XXE.",
    remediation="Disable external entities and DTDs (disallow-doctype-decl, external-general-entities=false) or use a hardened parser configuration.",
    tags=["security", "xxe"],
    cwe="CWE-611",
    owasp="A05:2021 Security Misconfiguration"
)

JAVA_JNDI_LOOKUP = Rule(
    id="megasast/java-jndi-lookup",
    name="Java JNDI lookup usage",
    description="JNDI lookups on attacker-controlled names can load remote classes and lead to remote code execution.",
    severity="MEDIUM",
    languages=["java"],
    queries={
        "java": "(method_invocation name: (identifier) @m (#eq? @m \"lookup\")) @match",
    },
    message="Use of JNDI lookup — remote class loading risk.",
    remediation="Never look up attacker-controlled names. Restrict JNDI to trusted providers and disable remote codebase loading.",
    tags=["security", "deserialization", "jndi"],
    cwe="CWE-829",
    owasp="A08:2021 Software and Data Integrity Failures"
)

JAVA_SSL_PROTOCOL = Rule(
    id="megasast/java-ssl-protocol",
    name="Java SSLContext with legacy SSL protocol",
    description="The SSL protocol version is deprecated and vulnerable; TLS must be used instead.",
    severity="LOW",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (identifier) @c name: (identifier) @m arguments: (argument_list (string_literal) @a) (#eq? @c \"SSLContext\") (#eq? @m \"getInstance\") (#eq? @a \"\\\"SSL\\\"\")) @match",
    },
    message="Legacy SSL protocol requested — deprecated and insecure.",
    remediation="Request TLSv1.2 or newer explicitly.",
    tags=["security", "tls", "cryptography"],
    cwe="CWE-327",
    owasp="A02:2021 Cryptographic Failures"
)

RULES = [JAVA_RUNTIME_EXEC, JAVA_PROCESSBUILDER, JAVA_READOBJECT, JAVA_SCRIPTENGINE_EVAL, JAVA_CIPHER_WEAK, JAVA_SIGNATURE_WEAK, JAVA_SQL_CONCAT, JAVA_XXE, JAVA_JNDI_LOOKUP, JAVA_MESSAGE_DIGEST_MD5, JAVA_MESSAGE_DIGEST_SHA1, JAVA_SSL_PROTOCOL]
