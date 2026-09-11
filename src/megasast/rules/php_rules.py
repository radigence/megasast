from megasast.rules.base import Rule

PHP_EVAL = Rule(
    id="megasast/php-eval",
    name="PHP eval() usage",
    description="eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f)"},
    message="Use of eval() — arbitrary code execution risk.",
    tags=["security", "injection"]
)

PHP_EXEC = Rule(
    id="megasast/php-exec",
    name="PHP exec() usage",
    description="exec() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f)"},
    message="Use of exec() — command injection risk.",
    tags=["security", "command-injection"]
)

PHP_SHELL_EXEC = Rule(
    id="megasast/php-shell-exec",
    name="PHP shell_exec() usage",
    description="shell_exec() can lead to command injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f)"},
    message="Use of shell_exec() — command injection risk.",
    tags=["security", "command-injection"]
)

PHP_UNSER = Rule(
    id="megasast/php-unserialize",
    name="PHP unserialize() usage",
    description="unserialize() can lead to object injection.",
    severity="HIGH",
    languages=["php"],
    queries={"php": "(function_call_expression (name) @f)"},
    message="Use of unserialize() — object injection risk.",
    tags=["security", "deserialization"]
)

RULES = [PHP_EVAL, PHP_EXEC, PHP_SHELL_EXEC, PHP_UNSER]
