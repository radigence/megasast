from megasast.rules.base import Rule

# Shell scripts are matched through the bash grammar (node types: command,
# command_name/word, pipeline). Rules deliberately avoid matching plain
# variable use; each pattern requires the dangerous command plus an
# aggravating token (piped download, dynamic evaluation, script sourcing
# through a variable).

SH_EVAL = Rule(
    id="megasast/sh-eval",
    name="Shell eval command usage",
    description="eval executes a constructed string as code; untrusted input reaching its arguments leads to arbitrary command execution.",
    severity="HIGH",
    languages=["bash"],
    queries={
        "bash": "(command (command_name (word) @c) (#eq? @c \"eval\")) @match",
    },
    message="Use of eval — arbitrary code execution risk.",
    remediation="Prefer executing a fixed executable with an argument array instead of re-evaluating a constructed string; validate input format strictly.",
    tags=["security", "command-injection"],
    cwe="CWE-95",
    owasp="A03:2021 Injection"
)

SH_CURL_PIPE_SH = Rule(
    id="megasast/sh-curl-pipe-sh",
    name="Shell curl/wget piped into a shell",
    description="Piping curl or wget output straight into sh or bash executes a remote payload with no integrity checks.",
    severity="HIGH",
    languages=["bash"],
    queries={
        "bash": "(pipeline (command (command_name (word) @c1)) (command (command_name (word) @c2)) (#match? @c1 \"^(curl|wget)$\") (#match? @c2 \"^(sh|bash|zsh|sudo)$\")) @match",
    },
    message="Downloaded script piped into a shell — remote code execution risk.",
    remediation="Download to a file, verify its checksum or signature, then execute.",
    tags=["security", "command-injection", "supply-chain"],
    cwe="CWE-494",
    owasp="A08:2021 Software and Data Integrity Failures"
)

SH_SOURCE_VARIABLE = Rule(
    id="megasast/sh-source-variable",
    name="Shell source of a variable path",
    description="Sourcing a path taken from a variable ($1, $SETUP_DIR, ...) executes whatever is at that path at runtime; positional arguments are attacker-controllable in many contexts (CI, install scripts).",
    severity="MEDIUM",
    languages=["bash"],
    queries={
        # source "$1" / source "$SOME_DIR/setup.sh"
        "bash": (
            "(command (command_name (word) @c) (string (simple_expansion)) (#eq? @c \"source\")) @match; "
            "(command (command_name (word) @c) (concatenation (simple_expansion)) (#eq? @c \"source\")) @match"
        ),
    },
    message="source executes a path taken from a variable — code execution risk.",
    remediation="Source only fixed, repository-controlled paths; validate and expand the script directory explicitly.",
    tags=["security", "command-injection"],
    cwe="CWE-94",
    owasp="A03:2021 Injection"
)

RULES = [SH_EVAL, SH_CURL_PIPE_SH, SH_SOURCE_VARIABLE]
