from megasast.rules.base import Rule

PHP_EVAL = Rule(
    id="megasast/php-eval",
    name="PHP eval() usage",
    description="eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"eval\")) @match"},
    message="Use of eval() — arbitrary code execution risk.",
    remediation="Avoid eval(). Use an explicit parser or a strict allow-list of supported operations.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PHP_EXEC = Rule(
    id="megasast/php-exec",
    name="PHP exec() usage",
    description="exec() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"exec\")) @match"},
    message="Use of exec() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_SHELL_EXEC = Rule(
    id="megasast/php-shell-exec",
    name="PHP shell_exec() usage",
    description="shell_exec() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"shell_exec\")) @match"},
    message="Use of shell_exec() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_UNSER = Rule(
    id="megasast/php-unserialize",
    name="PHP unserialize() usage",
    description="unserialize() can lead to object injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"unserialize\")) @match"},
    message="Use of unserialize() — object injection risk.",
    remediation="Do not unserialize untrusted data. Prefer JSON and validate the decoded structure.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

PHP_MD5 = Rule(
    id="megasast/php-md5",
    name="PHP md5() usage",
    description="MD5 is cryptographically broken and unsuitable for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"md5\")) @match"},
    message="Use of md5() — weak cryptographic hash.",
    remediation="Use password_hash() for passwords or SHA-256/SHA-3 for integrity checks.",
    tags=["security", "cryptography", "weak-hash"]
)

PHP_SHA1 = Rule(
    id="megasast/php-sha1",
    name="PHP sha1() usage",
    description="SHA-1 is deprecated for security-sensitive hashing because collision attacks are practical.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"sha1\")) @match"},
    message="Use of sha1() — weak cryptographic hash.",
    remediation="Use password_hash() for passwords or SHA-256/SHA-3 for integrity checks.",
    tags=["security", "cryptography", "weak-hash"]
)

RULES = [PHP_EVAL, PHP_EXEC, PHP_SHELL_EXEC, PHP_UNSER, PHP_MD5, PHP_SHA1]
