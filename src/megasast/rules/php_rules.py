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

PHP_SYSTEM = Rule(
    id="megasast/php-system",
    name="PHP system() usage",
    description="system() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"system\")) @match"},
    message="Use of system() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_PASSTHRU = Rule(
    id="megasast/php-passthru",
    name="PHP passthru() usage",
    description="passthru() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"passthru\")) @match"},
    message="Use of passthru() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_PROC_OPEN = Rule(
    id="megasast/php-proc-open",
    name="PHP proc_open() usage",
    description="proc_open() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"proc_open\")) @match"},
    message="Use of proc_open() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_POPEN = Rule(
    id="megasast/php-popen",
    name="PHP popen() usage",
    description="popen() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"popen\")) @match"},
    message="Use of popen() — command injection risk.",
    remediation="Avoid shell execution where possible. Use a fixed command and validate or allow-list untrusted arguments.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

PHP_ASSERT = Rule(
    id="megasast/php-assert",
    name="PHP assert() with string usage",
    description="assert() with a string argument evaluates it as PHP code and can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f arguments: (arguments (argument (string))) (#eq? @f \"assert\")) @match; (function_call_expression (name) @f arguments: (arguments (argument (encapsed_string))) (#eq? @f \"assert\")) @match"},
    message="Use of assert() with a string — arbitrary code execution risk.",
    remediation="Pass a boolean expression to assert() instead of a string. Never assert on attacker-controlled input.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PHP_CREATE_FUNCTION = Rule(
    id="megasast/php-create-function",
    name="PHP create_function() usage",
    description="create_function() evaluates its arguments as PHP code and can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"create_function\")) @match"},
    message="Use of create_function() — arbitrary code execution risk.",
    remediation="Replace create_function() with an anonymous function (closure).",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PHP_PREG_REPLACE_E = Rule(
    id="megasast/php-preg-replace-e",
    name="PHP preg_replace() with /e modifier",
    description="preg_replace() with the /e modifier evaluates the replacement as PHP code and can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f arguments: (arguments (argument (string (string_content) @re))) (#eq? @f \"preg_replace\") (#match? @re \"/[a-zA-Z]*e[a-zA-Z]*$\")) @match"},
    message="Use of preg_replace() with /e modifier — arbitrary code execution risk.",
    remediation="Remove the /e modifier and use preg_replace_callback() instead.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

PHP_CURL_NO_VERIFY = Rule(
    id="megasast/php-curl-no-verify",
    name="PHP curl with disabled TLS verification",
    description="CURLOPT_SSL_VERIFYPEER=false or CURLOPT_SSL_VERIFYHOST=false disables TLS certificate verification and enables man-in-the-middle attacks.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f arguments: (arguments (argument (name) @opt) (argument (boolean) @v)) (#eq? @f \"curl_setopt\") (#match? @opt \"^CURLOPT_SSL_VERIFY(PEER|HOST)$\") (#eq? @v \"false\")) @match"},
    message="TLS certificate verification is disabled (curl SSL verify option set to false).",
    remediation="Keep peer and host verification enabled and configure the expected CA bundle where appropriate.",
    tags=["security", "tls", "certificate-validation"],
    cwe="CWE-295",
    owasp="A02:2021 Cryptographic Failures"
)

PHP_INCLUDE_VARIABLE = Rule(
    id="megasast/php-include-variable",
    name="PHP include/require with variable",
    description="Including a file from a variable path can lead to local file inclusion. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(include_expression (variable_name) @v) @match; (require_expression (variable_name) @v) @match; (include_once_expression (variable_name) @v) @match; (require_once_expression (variable_name) @v) @match"},
    message="File inclusion from a variable path — local file inclusion risk.",
    remediation="Include only from an allow-list of known files. Never build the path from untrusted input.",
    tags=["security", "file-inclusion"],
    cwe="CWE-98",
    owasp="A03:2021 Injection"
)

PHP_REQUEST_SUPERGLOBAL = Rule(
    id="megasast/php-request-superglobal",
    name="PHP $_REQUEST usage",
    description="$_REQUEST merges GET, POST, and COOKIE input, obscuring the data source and weakening validation assumptions.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(variable_name (name) @n (#eq? @n \"_REQUEST\")) @match"},
    message="Use of $_REQUEST — ambiguous input source.",
    remediation="Read from $_GET, $_POST, or $_COOKIE explicitly and validate each input.",
    tags=["security", "input-validation"],
    cwe="CWE-20"
)

PHP_MCRYPT = Rule(
    id="megasast/php-mcrypt",
    name="PHP mcrypt_* usage",
    description="mcrypt is deprecated and its ciphers/modes (e.g. ECB, DES) are weak.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#match? @f \"^mcrypt_\")) @match"},
    message="Use of mcrypt — deprecated cryptography.",
    remediation="Use openssl_encrypt() with an authenticated mode such as AES-GCM, or sodium.",
    tags=["security", "cryptography", "weak-cipher"],
    cwe="CWE-327",
    owasp="A02:2021 Cryptographic Failures"
)

PHP_SQL_CONCAT = Rule(
    id="megasast/php-sql-concat",
    name="PHP SQL query built with concatenation",
    description="Building SQL with string concatenation can lead to SQL injection. Review whether any part is attacker-controlled.",
    severity="MEDIUM",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f arguments: (arguments (argument (binary_expression))) (#match? @f \"^(mysqli?_query|mysql_query|pg_query)$\")) @match; (member_call_expression (name) @m arguments: (arguments (argument (binary_expression))) (#eq? @m \"query\")) @match"},
    message="SQL built with string concatenation — potential SQL injection.",
    remediation="Use prepared statements with bound parameters and never concatenate untrusted input into SQL text.",
    tags=["security", "sqli"],
    cwe="CWE-89",
    owasp="A03:2021 Injection"
)

PHP_EXTRACT = Rule(
    id="megasast/php-extract",
    name="PHP extract() usage",
    description="extract() imports variables into scope and can overwrite trusted variables when run on untrusted data.",
    severity="LOW",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f (#eq? @f \"extract\")) @match"},
    message="Use of extract() — variable pollution risk.",
    remediation="Avoid extract(). Access array entries explicitly instead of importing them into scope.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

RULES = [PHP_EVAL, PHP_EXEC, PHP_SYSTEM, PHP_PASSTHRU, PHP_PROC_OPEN, PHP_POPEN, PHP_SHELL_EXEC, PHP_ASSERT, PHP_CREATE_FUNCTION, PHP_PREG_REPLACE_E, PHP_INCLUDE_VARIABLE, PHP_REQUEST_SUPERGLOBAL, PHP_UNSER, PHP_CURL_NO_VERIFY, PHP_SQL_CONCAT, PHP_MCRYPT, PHP_MD5, PHP_SHA1, PHP_EXTRACT]
