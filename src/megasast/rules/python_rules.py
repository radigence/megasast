from megasast.rules.base import Rule

PYTHON_EVAL = Rule(
    id="megasast/py-eval",
    name="Python eval() usage",
    description="Use of eval() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (identifier) @func (#eq? @func \"eval\"))"
    },
    message="Use of eval() — arbitrary code execution risk.",
    tags=["security", "injection"]
)

PYTHON_EXEC = Rule(
    id="megasast/py-exec",
    name="Python exec() usage",
    description="Use of exec() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (identifier) @func (#eq? @func \"exec\"))"
    },
    message="Use of exec() — arbitrary code execution risk.",
    tags=["security", "injection"]
)

PYTHON_OS_SYSTEM = Rule(
    id="megasast/py-os-system",
    name="Python os.system() usage",
    description="os.system() can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) @a (#eq? @obj \"os\") (#eq? @m \"system\"))"
    },
    message="Use of os.system() — command injection risk.",
    tags=["security", "command-injection"]
)

PYTHON_PICKLE_LOAD = Rule(
    id="megasast/py-pickle-load",
    name="Python pickle.load() usage",
    description="pickle.load() can lead to arbitrary code execution.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) @a (#eq? @obj \"pickle\") (#eq? @m \"load\"))"
    },
    message="Use of pickle.load() — arbitrary code execution risk.",
    tags=["security", "deserialization"]
)

PYTHON_YAML_LOAD = Rule(
    id="megasast/py-yaml-load",
    name="Python yaml.load() usage",
    description="yaml.load() without SafeLoader can lead to arbitrary code execution.",
    severity="MEDIUM",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) @a (#eq? @obj \"yaml\") (#eq? @m \"load\"))"
    },
    message="Use of yaml.load() — arbitrary code execution risk.",
    tags=["security", "deserialization"]
)

PYTHON_SUBPROCESS_SHELL = Rule(
    id="megasast/py-subprocess-shell",
    name="Python subprocess.Popen with shell=True",
    description="subprocess.Popen with shell=True can lead to command injection.",
    severity="HIGH",
    languages=["python"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) @a (#eq? @obj \"subprocess\") (#eq? @m \"Popen\"))"
    },
    message="Use of subprocess.Popen — check for shell=True.",
    tags=["security", "command-injection"]
)

RULES = [PYTHON_EVAL, PYTHON_EXEC, PYTHON_OS_SYSTEM, PYTHON_PICKLE_LOAD, PYTHON_YAML_LOAD, PYTHON_SUBPROCESS_SHELL]
