from megasast.rules.base import Rule

RUST_COMMAND_NEW = Rule(
    id="megasast/rust-command",
    name="Rust std::process::Command usage",
    description="std::process::Command can lead to command injection.",
    severity="HIGH",
    languages=["rust"],
    queries={
        "rust": "(call_expression (scoped_identifier) @call (#match? @call \"^(std::process::)?Command::new$\")) @match",
    },
    message="Use of std::process::Command — command injection risk.",
    tags=["security", "command-injection"],
    cwe="CWE-78",
    owasp="A03:2021 Injection"
)

RUST_UNSAFE = Rule(
    id="megasast/rust-unsafe",
    name="Rust unsafe block usage",
    description="unsafe blocks bypass Rust's safety guarantees and can lead to undefined behavior.",
    severity="LOW",
    languages=["rust"],
    queries={
        "rust": "(unsafe_block) @match",
    },
    message="Use of an unsafe block — soundness risk.",
    tags=["security", "unsoundness"],
    cwe="CWE-119",
    owasp="A04:2021 Insecure Design"
)

RUST_TRANSMUTE = Rule(
    id="megasast/rust-transmute",
    name="Rust mem::transmute usage",
    description="mem::transmute can lead to undefined behavior from invalid type punning.",
    severity="MEDIUM",
    languages=["rust"],
    queries={
        "rust": "(call_expression (scoped_identifier) @call (#match? @call \"^(std::mem::|mem::)transmute$\")) @match",
    },
    message="Use of mem::transmute — undefined behavior risk.",
    tags=["security", "type-punning"],
    cwe="CWE-119",
    owasp="A04:2021 Insecure Design"
)

RULES = [RUST_COMMAND_NEW, RUST_UNSAFE, RUST_TRANSMUTE]
