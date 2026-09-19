from megasast.rules.base import Rule

JS_EVAL = Rule(
    id="megasast/js-eval",
    name="JavaScript eval() usage",
    description="Use of eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (identifier) @f (#eq? @f \"eval\")) @match",
        "typescript": "(call_expression function: (identifier) @f (#eq? @f \"eval\")) @match",
    },
    message="Use of eval() — arbitrary code execution risk.",
    remediation="Avoid eval(). Parse the expected data format and use an allow-list for supported operations.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

JS_NEW_FUNCTION = Rule(
    id="megasast/js-new-function",
    name="JavaScript new Function() usage",
    description="new Function() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(new_expression constructor: (identifier) @f (#eq? @f \"Function\")) @match",
        "typescript": "(new_expression constructor: (identifier) @f (#eq? @f \"Function\")) @match",
    },
    message="Use of new Function() — arbitrary code execution risk.",
    remediation="Avoid dynamic function construction. Use explicit functions or a constrained expression parser.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

JS_INNERHTML = Rule(
    id="megasast/js-innerhtml",
    name="Assignment to innerHTML",
    description="Assigning to innerHTML can lead to XSS.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"innerHTML\"))) @match",
        "typescript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"innerHTML\"))) @match",
    },
    message="Assignment to innerHTML — potential XSS.",
    remediation="Prefer textContent for text. If HTML is required, sanitize it with a vetted allow-list sanitizer before assignment.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

JS_CHILD_PROCESS_EXEC = Rule(
    id="megasast/js-child-process-exec",
    name="JavaScript child_process.exec usage",
    description="Direct child_process.exec calls can lead to command injection.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"child_process\") (#eq? @p \"exec\"))) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"child_process\") (#eq? @p \"exec\"))) @match",
    },
    message="Use of child_process.exec — command injection risk.",
    remediation="Prefer execFile or spawn with a fixed executable and argument array; validate untrusted input.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

JS_CHILD_PROCESS_EXEC_SYNC = Rule(
    id="megasast/js-child-process-exec-sync",
    name="JavaScript child_process.execSync usage",
    description="Direct child_process.execSync calls can lead to command injection and block the event loop.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"child_process\") (#eq? @p \"execSync\"))) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"child_process\") (#eq? @p \"execSync\"))) @match",
    },
    message="Use of child_process.execSync — command injection risk.",
    remediation="Prefer execFile or spawn with a fixed executable and argument array; validate untrusted input.",
    tags=["security", "command-injection"]
)

JS_DOCUMENT_WRITE = Rule(
    id="megasast/js-document-write",
    name="JavaScript document.write usage",
    description="document.write can introduce cross-site scripting when the written content is attacker-controlled.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"document\") (#eq? @p \"write\"))) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p (#eq? @obj \"document\") (#eq? @p \"write\"))) @match",
    },
    message="Use of document.write — potential XSS.",
    remediation="Use safe DOM APIs such as textContent or createElement. Sanitize untrusted HTML before insertion.",
    tags=["security", "xss"]
)

JS_VM_RUNINCONTEXT = Rule(
    id="megasast/js-vm-runincontext",
    name="JavaScript vm.runIn*() usage",
    description="vm.runInNewContext()/runInThisContext()/runInContext() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) (#eq? @obj \"vm\") (#match? @p \"^(runInNewContext|runInThisContext|runInContext)$\")) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) (#eq? @obj \"vm\") (#match? @p \"^(runInNewContext|runInThisContext|runInContext)$\")) @match",
    },
    message="Use of vm.runIn*() — arbitrary code execution risk.",
    remediation="Avoid executing dynamic code. If untrusted code must run, isolate it in a separate process with strict resource limits.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

JS_SPAWN_SHELL = Rule(
    id="megasast/js-spawn-shell",
    name="JavaScript child_process.spawn with shell:true",
    description="child_process.spawn with shell:true can lead to command injection.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (object (pair key: (property_identifier) @k value: (true)) (#eq? @k \"shell\"))) (#eq? @obj \"child_process\") (#eq? @p \"spawn\")) @match; (call_expression function: (identifier) @f arguments: (arguments (object (pair key: (property_identifier) @k value: (true)) (#eq? @k \"shell\"))) (#eq? @f \"spawn\")) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (object (pair key: (property_identifier) @k value: (true)) (#eq? @k \"shell\"))) (#eq? @obj \"child_process\") (#eq? @p \"spawn\")) @match; (call_expression function: (identifier) @f arguments: (arguments (object (pair key: (property_identifier) @k value: (true)) (#eq? @k \"shell\"))) (#eq? @f \"spawn\")) @match",
    },
    message="Use of child_process.spawn with shell:true — command injection risk.",
    remediation="Prefer execFile or spawn without shell using a fixed executable and argument array; validate untrusted input.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

JS_REJECT_UNAUTHORIZED = Rule(
    id="megasast/js-reject-unauthorized",
    name="JavaScript rejectUnauthorized:false usage",
    description="rejectUnauthorized:false disables TLS certificate verification and enables man-in-the-middle attacks.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(pair key: (property_identifier) @k value: (false) (#eq? @k \"rejectUnauthorized\")) @match",
        "typescript": "(pair key: (property_identifier) @k value: (false) (#eq? @k \"rejectUnauthorized\")) @match",
    },
    message="TLS certificate verification is disabled (rejectUnauthorized:false).",
    remediation="Keep certificate verification enabled and configure the expected CA bundle where appropriate.",
    tags=["security", "tls", "certificate-validation"],
    cwe="CWE-295",
    owasp="A02:2021 Cryptographic Failures"
)

JS_OUTERHTML = Rule(
    id="megasast/js-outerhtml",
    name="Assignment to outerHTML",
    description="Assigning to outerHTML can lead to XSS.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"outerHTML\"))) @match",
        "typescript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"outerHTML\"))) @match",
    },
    message="Assignment to outerHTML — potential XSS.",
    remediation="Prefer textContent for text. If HTML is required, sanitize it with a vetted allow-list sanitizer before assignment.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

JS_INSERT_ADJACENT_HTML = Rule(
    id="megasast/js-insert-adjacent-html",
    name="JavaScript insertAdjacentHTML usage",
    description="insertAdjacentHTML parses its argument as HTML and can lead to XSS.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression property: (property_identifier) @p) (#eq? @p \"insertAdjacentHTML\")) @match",
        "typescript": "(call_expression function: (member_expression property: (property_identifier) @p) (#eq? @p \"insertAdjacentHTML\")) @match",
    },
    message="Use of insertAdjacentHTML — potential XSS.",
    remediation="Prefer safe DOM APIs such as textContent or createElement. Sanitize untrusted HTML before insertion.",
    tags=["security", "xss"],
    cwe="CWE-79",
    owasp="A03:2021 Injection"
)

JS_LOCALSTORAGE_SECRET = Rule(
    id="megasast/js-localstorage-secret",
    name="JavaScript secret stored in web storage",
    description="Storing tokens or credentials in localStorage/sessionStorage exposes them to any script running on the page.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (string (string_fragment) @k)) (#match? @obj \"^(localStorage|sessionStorage)$\") (#eq? @p \"setItem\") (#match? @k \"(?i)(token|password|passwd|secret|auth|credential|api_?key)\")) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (string (string_fragment) @k)) (#match? @obj \"^(localStorage|sessionStorage)$\") (#eq? @p \"setItem\") (#match? @k \"(?i)(token|password|passwd|secret|auth|credential|api_?key)\")) @match",
    },
    message="Secret stored in web storage — accessible to any page script.",
    remediation="Keep tokens in httpOnly, Secure cookies or in memory. Never persist long-lived secrets in web storage.",
    tags=["security", "secrets", "insecure-storage"],
    cwe="CWE-922"
)

JS_CRYPTO_WEAK_HASH = Rule(
    id="megasast/js-crypto-weak-hash",
    name="JavaScript crypto.createHash with weak algorithm",
    description="MD5, SHA-1, and MD4 are broken or deprecated for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (string (string_fragment) @a)) (#eq? @obj \"crypto\") (#eq? @p \"createHash\") (#match? @a \"(?i)^(md5|sha1|md4)$\")) @match; (call_expression function: (identifier) @f arguments: (arguments (string (string_fragment) @a)) (#eq? @f \"createHash\") (#match? @a \"(?i)^(md5|sha1|md4)$\")) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) arguments: (arguments (string (string_fragment) @a)) (#eq? @obj \"crypto\") (#eq? @p \"createHash\") (#match? @a \"(?i)^(md5|sha1|md4)$\")) @match; (call_expression function: (identifier) @f arguments: (arguments (string (string_fragment) @a)) (#eq? @f \"createHash\") (#match? @a \"(?i)^(md5|sha1|md4)$\")) @match",
    },
    message="Weak hash algorithm in crypto.createHash — collision and preimage risk.",
    remediation="Use SHA-256 or stronger for integrity checks, or a dedicated password hashing function for passwords.",
    tags=["security", "cryptography", "weak-hash"],
    cwe="CWE-328",
    owasp="A02:2021 Cryptographic Failures"
)

JS_SETTIMEOUT_STRING = Rule(
    id="megasast/js-settimeout-string",
    name="JavaScript setTimeout/setInterval with string",
    description="Passing a string to setTimeout()/setInterval() evaluates it as code, like eval().",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (identifier) @f arguments: (arguments (string)) (#match? @f \"^(setTimeout|setInterval)$\")) @match",
        "typescript": "(call_expression function: (identifier) @f arguments: (arguments (string)) (#match? @f \"^(setTimeout|setInterval)$\")) @match",
    },
    message="setTimeout/setInterval with a string — arbitrary code execution risk.",
    remediation="Pass a function reference instead of a string.",
    tags=["security", "injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

RULES = [
    JS_EVAL, JS_NEW_FUNCTION, JS_INNERHTML, JS_OUTERHTML, JS_INSERT_ADJACENT_HTML,
    JS_CHILD_PROCESS_EXEC, JS_CHILD_PROCESS_EXEC_SYNC, JS_DOCUMENT_WRITE,
    JS_VM_RUNINCONTEXT, JS_SPAWN_SHELL, JS_REJECT_UNAUTHORIZED,
    JS_LOCALSTORAGE_SECRET, JS_CRYPTO_WEAK_HASH, JS_SETTIMEOUT_STRING,
]
