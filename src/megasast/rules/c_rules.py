from megasast.rules.base import Rule

C_SYSTEM = Rule(
    id="megasast/c-system",
    name="C system() usage",
    description="system() can lead to command injection.",
    severity="HIGH",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"system\"))",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"system\"))",
    },
    message="Use of system() — command injection risk.",
    tags=["security", "command-injection"]
)

C_STRCPY = Rule(
    id="megasast/c-strcpy",
    name="C strcpy() usage",
    description="strcpy() can lead to buffer overflow.",
    severity="MEDIUM",
    languages=["c", "cpp"],
    queries={
        "c": "(call_expression function: (identifier) @f (#eq? @f \"strcpy\"))",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"strcpy\"))",
    },
    message="Use of strcpy() — buffer overflow risk.",
    tags=["security", "buffer-overflow"]
)

RULES = [C_SYSTEM, C_STRCPY]
