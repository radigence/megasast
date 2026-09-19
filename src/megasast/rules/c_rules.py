from megasast.rules.base import Rule

C_SYSTEM = Rule(
    id="megasast/c-system",
    name="C system() usage",
    description="system() can lead to command injection.",
    severity="HIGH",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"system\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"system\")) @match",
    },
    message="Use of system() — command injection risk.",
    remediation="Avoid system(). Use execve or a similar API with a fixed executable and validated argument vector.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

C_STRCPY = Rule(
    id="megasast/c-strcpy",
    name="C strcpy() usage",
    description="strcpy() can lead to buffer overflow.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"strcpy\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"strcpy\")) @match",
    },
    message="Use of strcpy() — buffer overflow risk.",
    remediation="Use a length-bounded copy and validate destination capacity before copying data.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-120",
    owasp="A04:2021 Insecure Design"
)

C_GETS = Rule(
    id="megasast/c-gets",
    name="C gets() usage",
    description="gets() cannot limit input length and can overflow the destination buffer.",
    severity="HIGH",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"gets\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"gets\")) @match",
    },
    message="Use of gets() — buffer overflow risk.",
    remediation="Use fgets() or another bounded input API and validate the resulting input.",
    tags=["security", "buffer-overflow"]
)

C_SPRINTF = Rule(
    id="megasast/c-sprintf",
    name="C sprintf() usage",
    description="sprintf() does not know the destination buffer size and can overflow it.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"sprintf\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"sprintf\")) @match",
    },
    message="Use of sprintf() — buffer overflow risk.",
    remediation="Use snprintf() with the destination buffer size and check for truncation.",
    tags=["security", "buffer-overflow"]
)

C_STRCAT = Rule(
    id="megasast/c-strcat",
    name="C strcat() usage",
    description="strcat() can overflow the destination buffer because it does not receive its capacity.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"strcat\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"strcat\")) @match",
    },
    message="Use of strcat() — buffer overflow risk.",
    remediation="Use a capacity-aware string builder or verify the destination capacity before concatenation.",
    tags=["security", "buffer-overflow"]
)

C_POPEN = Rule(
    id="megasast/c-popen",
    name="C popen() usage",
    description="popen() can lead to command injection.",
    severity="HIGH",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"popen\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"popen\")) @match",
    },
    message="Use of popen() — command injection risk.",
    remediation="Avoid popen(). Use execve or a similar API with a fixed executable and validated argument vector.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

C_SCANF_S = Rule(
    id="megasast/c-scanf-s",
    name="C scanf() with %s format",
    description="scanf() with %s performs unbounded input and can overflow the destination buffer.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f arguments: (argument_list (string_literal) @fmt) (#match? @f \"^(f|s)?scanf$\") (#match? @fmt \"%s\")) @match",
        "cpp": "(call_expression function: (identifier) @f arguments: (argument_list (string_literal) @fmt) (#match? @f \"^(f|s)?scanf$\") (#match? @fmt \"%s\")) @match",
    },
    message="Use of scanf() with %s — buffer overflow risk.",
    remediation="Use a field width (e.g. %63s) or a bounded input API and validate the result.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-120",
    owasp="A04:2021 Insecure Design"
)

C_MEMCPY = Rule(
    id="megasast/c-memcpy",
    name="C memcpy() usage",
    description="memcpy() does not check bounds; a wrong length can overflow the destination or read past the source.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"memcpy\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"memcpy\")) @match",
    },
    message="Use of memcpy() — buffer overflow risk.",
    remediation="Verify the length against both buffers before copying, or use a bounds-checked alternative.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-120",
    owasp="A04:2021 Insecure Design"
)

C_OPENSSL_WEAK_HASH = Rule(
    id="megasast/c-openssl-weak-hash",
    name="C OpenSSL MD5/SHA-1 usage",
    description="MD5 and SHA-1 are broken or deprecated for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#match? @f \"^(MD5|SHA1)(_|$)\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#match? @f \"^(MD5|SHA1)(_|$)\")) @match",
    },
    message="Use of OpenSSL MD5/SHA-1 — weak cryptographic hash.",
    remediation="Use SHA-256 or stronger via EVP for integrity checks.",
    tags=["security", "cryptography", "weak-hash"],
    cwe="CWE-328",
    owasp="A02:2021 Cryptographic Failures"
)

C_WEAK_CIPHER = Rule(
    id="megasast/c-weak-cipher",
    name="C DES/RC4 usage",
    description="DES and RC4 are broken and must not be used for encryption.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#match? @f \"^(DES_|RC4)\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#match? @f \"^(DES_|RC4)\")) @match",
    },
    message="Use of DES/RC4 — broken cipher.",
    remediation="Use AES/GCM or another modern authenticated cipher via EVP.",
    tags=["security", "cryptography", "weak-cipher"],
    cwe="CWE-327",
    owasp="A02:2021 Cryptographic Failures"
)

C_MKTEMP = Rule(
    id="megasast/c-mktemp",
    name="C mktemp() usage",
    description="mktemp() only returns a filename and is vulnerable to symlink race conditions.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"mktemp\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"mktemp\")) @match",
    },
    message="Use of mktemp() — insecure temporary file creation.",
    remediation="Use mkstemp() or tmpfile() to create the file atomically.",
    tags=["security", "race-condition", "temporary-files"],
    cwe="CWE-377"
)

C_SETUID = Rule(
    id="megasast/c-setuid",
    name="C setuid()/seteuid() usage",
    description="Changing process privileges is error-prone and can leave excessive privileges in reachable code.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#match? @f \"^set[eu]id$\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#match? @f \"^set[eu]id$\")) @match",
    },
    message="Use of setuid()/seteuid() — privilege management risk.",
    remediation="Drop privileges permanently and as early as possible; verify the change succeeded and runs with least privilege.",
    tags=["security", "privileges"],
    cwe="CWE-250",
    owasp="A01:2021 Broken Access Control"
)

C_CHMOD_777 = Rule(
    id="megasast/c-chmod-777",
    name="C chmod() with 0777",
    description="chmod() with 0777 grants read/write/execute to everyone.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f arguments: (argument_list (number_literal) @mode) (#eq? @f \"chmod\") (#eq? @mode \"0777\")) @match",
        "cpp": "(call_expression function: (identifier) @f arguments: (argument_list (number_literal) @mode) (#eq? @f \"chmod\") (#eq? @mode \"0777\")) @match",
    },
    message="Use of chmod() with 0777 — overly broad file permissions.",
    remediation="Grant the minimal permissions required.",
    tags=["security", "permissions"],
    cwe="CWE-732",
    owasp="A01:2021 Broken Access Control"
)

C_GETWD = Rule(
    id="megasast/c-getwd",
    name="C getwd() usage",
    description="getwd() does not take a buffer size and can overflow the destination buffer.",
    severity="LOW",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"getwd\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"getwd\")) @match",
    },
    message="Use of getwd() — buffer overflow risk.",
    remediation="Use getcwd() with an explicit buffer size.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-676"
)

C_STRTOK = Rule(
    id="megasast/c-strtok",
    name="C strtok() usage",
    description="strtok() modifies its input in place, keeps hidden global state, and is not thread-safe.",
    severity="LOW",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"strtok\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"strtok\")) @match",
    },
    message="Use of strtok() — unsafe string tokenization.",
    remediation="Use strtok_r() or an explicit, bounds-checked parser.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-676"
)

C_ATOI = Rule(
    id="megasast/c-atoi",
    name="C atoi()/atol()/atof() usage",
    description="atoi() and friends perform no error checking; invalid input silently yields 0 and overflow is undefined.",
    severity="LOW",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#match? @f \"^ato(i|l|f)$\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#match? @f \"^ato(i|l|f)$\")) @match",
    },
    message="Use of atoi()/atol()/atof() — unchecked conversion.",
    remediation="Use strtol()/strtod() and check errno and the end pointer.",
    tags=["security", "input-validation"],
    cwe="CWE-676"
)

RULES = [C_SYSTEM, C_POPEN, C_STRCPY, C_GETS, C_SPRINTF, C_STRCAT, C_SCANF_S, C_MEMCPY, C_OPENSSL_WEAK_HASH, C_WEAK_CIPHER, C_MKTEMP, C_SETUID, C_CHMOD_777, C_GETWD, C_STRTOK, C_ATOI]
