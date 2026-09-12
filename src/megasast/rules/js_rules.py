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
    tags=["security", "injection"]
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
    tags=["security", "injection"]
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
    tags=["security", "xss"]
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
    tags=["security", "command-injection"]
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

RULES = [
    JS_EVAL, JS_NEW_FUNCTION, JS_INNERHTML, JS_CHILD_PROCESS_EXEC,
    JS_CHILD_PROCESS_EXEC_SYNC, JS_DOCUMENT_WRITE,
]
