from megasast.rules.base import Rule

JAVA_RUNTIME_EXEC = Rule(
    id="megasast/java-runtime-exec",
    name="Java Runtime.exec() usage",
    description="Runtime.exec() can lead to command injection.",
    severity="HIGH",
    languages=["java"],
    queries={
        "java": "(method_invocation object: (method_invocation) @inner name: (identifier) @m (#eq? @m \"exec\"))",
    },
    message="Use of Runtime.exec() — command injection risk.",
    tags=["security", "command-injection"]
)

RULES = [JAVA_RUNTIME_EXEC]
