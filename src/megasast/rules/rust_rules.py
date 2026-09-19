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

RUST_DANGER_ACCEPT_INVALID = Rule(
    id="megasast/rust-danger-accept-invalid",
    name="Rust danger_accept_invalid_certs/hostnames usage",
    description="danger_accept_invalid_certs()/danger_accept_invalid_hostnames() disables TLS certificate verification and enables man-in-the-middle attacks.",
    severity="HIGH",
    languages=["rust"],
    queries={
        "rust": "(call_expression function: (field_expression field: (field_identifier) @f) (#match? @f \"^danger_accept_invalid_(certs|hostnames)$\")) @match",
    },
    message="TLS certificate verification is disabled (danger_accept_invalid_*).",
    remediation="Keep certificate verification enabled and configure the expected CA roots where appropriate.",
    tags=["security", "tls", "certificate-validation"],
    cwe="CWE-295",
    owasp="A02:2021 Cryptographic Failures"
)

RUST_FROM_UTF8_UNCHECKED = Rule(
    id="megasast/rust-from-utf8-unchecked",
    name="Rust String::from_utf8_unchecked usage",
    description="from_utf8_unchecked() skips UTF-8 validation; invalid bytes cause undefined behavior.",
    severity="MEDIUM",
    languages=["rust"],
    queries={
        "rust": "(call_expression function: [(scoped_identifier) @f (field_expression field: (field_identifier) @f)] (#match? @f \"from_utf8_unchecked$\")) @match",
    },
    message="Use of from_utf8_unchecked() — undefined behavior risk on invalid UTF-8.",
    remediation="Use String::from_utf8() and handle the error, or validate with std::str::from_utf8() first.",
    tags=["security", "type-confusion"],
    cwe="CWE-704",
    owasp="A04:2021 Insecure Design"
)

RUST_MEM_ZEROED = Rule(
    id="megasast/rust-mem-zeroed",
    name="Rust mem::zeroed usage",
    description="mem::zeroed() is undefined behavior for types with invalid zero values such as bool, references, or NonZero integers.",
    severity="MEDIUM",
    languages=["rust"],
    queries={
        "rust": "(call_expression (scoped_identifier) @c (#match? @c \"^(std::mem::|mem::)?zeroed$\")) @match",
    },
    message="Use of mem::zeroed() — undefined behavior risk for non-zeroable types.",
    remediation="Use Default::default(), MaybeUninit, or an explicit valid initializer instead.",
    tags=["security", "uninitialized-memory"],
    cwe="CWE-704",
    owasp="A04:2021 Insecure Design"
)

RUST_SLICE_RAW_PARTS = Rule(
    id="megasast/rust-slice-raw-parts",
    name="Rust from_raw_parts usage",
    description="from_raw_parts() trusts a raw pointer and length; mistakes cause out-of-bounds access and undefined behavior.",
    severity="MEDIUM",
    languages=["rust"],
    queries={
        "rust": "(call_expression (scoped_identifier) @c (#match? @c \"from_raw_parts$\")) @match",
    },
    message="Use of from_raw_parts() — out-of-bounds and undefined behavior risk.",
    remediation="Prefer safe abstractions. If raw parts are required, document and audit the pointer validity, alignment, length, and aliasing invariants.",
    tags=["security", "buffer-overflow"],
    cwe="CWE-822",
    owasp="A04:2021 Insecure Design"
)

RUST_WEAK_HASH_IMPORT = Rule(
    id="megasast/rust-weak-hash-import",
    name="Rust md5/sha1 crate usage",
    description="The md5 and sha1 crates provide broken or deprecated hashes, unsuitable for security-sensitive hashing.",
    severity="MEDIUM",
    languages=["rust"],
    queries={
        "rust": "(use_declaration (scoped_identifier) @u (#match? @u \"^(md5|sha1)::\")) @match; (use_declaration (identifier) @u (#match? @u \"^(md5|sha1)$\")) @match",
    },
    message="Use of the md5/sha1 crate — weak cryptographic hash.",
    remediation="Use the sha2 crate (SHA-256 or stronger), or a dedicated password hashing crate for passwords.",
    tags=["security", "cryptography", "weak-hash"],
    cwe="CWE-328",
    owasp="A02:2021 Cryptographic Failures"
)

RULES = [RUST_COMMAND_NEW, RUST_DANGER_ACCEPT_INVALID, RUST_UNSAFE, RUST_TRANSMUTE, RUST_FROM_UTF8_UNCHECKED, RUST_MEM_ZEROED, RUST_SLICE_RAW_PARTS, RUST_WEAK_HASH_IMPORT]
