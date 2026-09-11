from megasast.rules.base import Rule

GO_EXEC_CMD = Rule(
    id="megasast/go-exec-cmd",
    name="Go exec.Command usage",
    description="exec.Command can lead to command injection.",
    severity="HIGH",
    languages=["go"],
    queries={
        "go": "(call_expression function: (selector_expression) @sel (#eq? @sel \"exec.Command\"))",
    },
    message="Use of exec.Command — command injection risk.",
    tags=["security", "command-injection"]
)

RULES = [GO_EXEC_CMD]
