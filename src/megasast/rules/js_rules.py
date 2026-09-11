from megasast.rules.base import Rule

JS_EVAL = Rule(
    id="megasast/js-eval",
    name="JavaScript eval() usage",
    description="Use of eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (identifier) @f (#eq? @f \"eval\"))",
        "typescript": "(call_expression function: (identifier) @f (#eq? @f \"eval\"))",
    },
    message="Use of eval() — arbitrary code execution risk.",
    tags=["security", "injection"]
)

JS_NEW_FUNCTION = Rule(
    id="megasast/js-new-function",
    name="JavaScript new Function() usage",
    description="new Function() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(new_expression constructor: (identifier) @f (#eq? @f \"Function\"))",
        "typescript": "(new_expression constructor: (identifier) @f (#eq? @f \"Function\"))",
    },
    message="Use of new Function() — arbitrary code execution risk.",
    tags=["security", "injection"]
)

JS_INNERHTML = Rule(
    id="megasast/js-innerhtml",
    name="Assignment to innerHTML",
    description="Assigning to innerHTML can lead to XSS.",
    severity="MEDIUM",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"innerHTML\")))",
        "typescript": "(assignment_expression left: (member_expression property: (property_identifier) @p (#eq? @p \"innerHTML\")))",
    },
    message="Assignment to innerHTML — potential XSS.",
    tags=["security", "xss"]
)

JS_CHILD_PROCESS_EXEC = Rule(
    id="megasast/js-child-process-exec",
    name="child_process.exec usage",
    description="child_process.exec can lead to command injection.",
    severity="HIGH",
    languages=["javascript", "typescript"],
    queries={
        "javascript": "(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p \"exec\")))",
        "typescript": "(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p \"exec\")))",
    },
    message="Use of child_process.exec — command injection risk.",
    tags=["security", "command-injection"]
)

RULES = [JS_EVAL, JS_NEW_FUNCTION, JS_INNERHTML, JS_CHILD_PROCESS_EXEC]
