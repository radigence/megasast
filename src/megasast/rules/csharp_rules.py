from megasast.rules.base import Rule

# C#: matched via the csharp grammar (invocation_expression /
# member_access_expression / object_creation_expression). The `.` anchor
# keeps member_access captures order-controlled (receiver then member).

CSHARP_PROCESS_START = Rule(
    id="megasast/csharp-process-start",
    name="C# Process.Start usage",
    description="Process.Start runs an external process; a command string assembled from untrusted input leads to command injection.",
    severity="MEDIUM",
    languages=["csharp"],
    queries={
        "csharp": "(invocation_expression function: (member_access_expression (identifier) @recv . (identifier) @m) (#eq? @recv \"Process\") (#eq? @m \"Start\")) @match",
    },
    message="Use of Process.Start — command injection risk.",
    remediation="Use the ProcessStartInfo overload with an argument list and UseShellExecute=false; validate any user-controlled input.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

CSHARP_SHELL_EXECUTE = Rule(
    id="megasast/csharp-shell-execute",
    name="C# ProcessStartInfo UseShellExecute=true",
    description="UseShellExecute=true resolves the command through the host shell, which exposes string-built commands to injection and path trickery.",
    severity="HIGH",
    languages=["csharp"],
    queries={
        "csharp": "(object_creation_expression (identifier) @type (initializer_expression (assignment_expression (identifier) @prop (boolean_literal) @val)) (#eq? @type \"ProcessStartInfo\") (#eq? @prop \"UseShellExecute\") (#eq? @val \"true\")) @match",
    },
    message="ProcessStartInfo configured with UseShellExecute — command injection risk.",
    remediation="Use UseShellExecute=false and pass an explicit argument list; restrict the working directory and executable path.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

RULES = [CSHARP_PROCESS_START, CSHARP_SHELL_EXECUTE]
