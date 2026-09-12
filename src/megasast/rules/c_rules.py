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
    tags=["security", "command-injection"]
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
    tags=["security", "buffer-overflow"]
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

RULES = [C_SYSTEM, C_STRCPY, C_GETS, C_SPRINTF, C_STRCAT]
