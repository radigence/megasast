from megasast.rules.base import Rule

AWS_ACCESS_KEY = Rule(
    id="megasast/aws-access-key",
    name="Hardcoded AWS access key ID",
    description="A hardcoded AWS access key ID (AKIA...) exposes cloud credentials to anyone with repository access.",
    severity="HIGH",
    languages=["python", "javascript", "typescript", "java", "c", "cpp", "go", "php", "rust"],
    queries={
        "python": '(string (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "javascript": '(string (string_fragment) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "typescript": '(string (string_fragment) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "java": '(string_literal (string_fragment) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "c": '(string_literal (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "cpp": '(string_literal (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "go": '(interpreted_string_literal (interpreted_string_literal_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match; (raw_string_literal (raw_string_literal_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "php": '(encapsed_string (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match; (string (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
        "rust": '(string_literal (string_content) @s (#match? @s "AKIA[0-9A-Z]{16}")) @match',
    },
    message="Hardcoded AWS access key ID — credential exposure risk.",
    remediation="Revoke the exposed key. Load credentials from a secrets manager or environment at runtime, never from source.",
    tags=["security", "secrets", "hardcoded-credentials"],
    cwe="CWE-798",
    owasp="A07:2021 Identification and Authentication Failures"
)

HARDCODED_SECRET = Rule(
    id="megasast/hardcoded-secret",
    name="Hardcoded secret in source",
    description="A string literal assigned to a password/secret/token-like variable may expose credentials in source control.",
    severity="MEDIUM",
    languages=["python", "javascript", "typescript", "java", "c", "cpp", "go", "php", "rust"],
    queries={
        "python": "(assignment left: (identifier) @name right: (string (string_content) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{8,}\")) @match",
        "javascript": "(variable_declarator name: (identifier) @name value: (string (string_fragment) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{8,}\")) @match; (assignment_expression left: (identifier) @name right: (string (string_fragment) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{8,}\")) @match",
        "typescript": "(variable_declarator name: (identifier) @name value: (string (string_fragment) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{8,}\")) @match; (assignment_expression left: (identifier) @name right: (string (string_fragment) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{8,}\")) @match",
        "java": "(variable_declarator name: (identifier) @name value: (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
        "c": "(assignment_expression left: (identifier) @name right: (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match; (init_declarator declarator: (_) @name value: (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
        "cpp": "(assignment_expression left: (identifier) @name right: (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match; (init_declarator declarator: (_) @name value: (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
        "go": "(short_var_declaration (expression_list (identifier) @name) (expression_list (interpreted_string_literal) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match; (var_spec (identifier) @name (expression_list (interpreted_string_literal) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match; (assignment_statement (expression_list (identifier) @name) (expression_list (interpreted_string_literal) @v) (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
        "php": "(assignment_expression (variable_name) @name (encapsed_string) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match; (assignment_expression (variable_name) @name (string) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
        "rust": "(let_declaration (identifier) @name (string_literal) @v (#match? @name \"(?i)(password|passwd|secret|token|api_?key|credential|private_?key)\") (#match? @v \".{10,}\")) @match",
    },
    message="Possible hardcoded secret — credential exposure risk.",
    remediation="Move the secret to a secrets manager or environment variable injected at runtime. If it was committed, rotate it.",
    tags=["security", "secrets", "hardcoded-credentials"],
    cwe="CWE-798",
    owasp="A07:2021 Identification and Authentication Failures"
)

INSECURE_RAND = Rule(
    id="megasast/insecure-rand",
    name="Predictable random number generator",
    description="Non-cryptographic PRNGs (random, Math.random, rand, math/rand) are predictable and unsuitable for tokens, salts, or session identifiers.",
    severity="MEDIUM",
    languages=["python", "javascript", "typescript", "java", "c", "cpp", "go", "php"],
    queries={
        "python": "(call function: (attribute object: (identifier) @obj attribute: (identifier) @m) (#eq? @obj \"random\") (#match? @m \"^(random|choice|randint|randrange|shuffle|sample|uniform)$\")) @match",
        "javascript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) (#eq? @obj \"Math\") (#eq? @p \"random\")) @match",
        "typescript": "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @p) (#eq? @obj \"Math\") (#eq? @p \"random\")) @match",
        "java": "(method_invocation object: (identifier) @o name: (identifier) @m (#eq? @o \"Math\") (#eq? @m \"random\")) @match; (object_creation_expression type: (type_identifier) @t (#eq? @t \"Random\")) @match",
        "c": "(call_expression function: (identifier) @f (#eq? @f \"rand\")) @match",
        "cpp": "(call_expression function: (identifier) @f (#eq? @f \"rand\")) @match",
        "go": "(import_spec path: (interpreted_string_literal) @path (#eq? @path \"\\\"math/rand\\\"\")) @match",
        "php": "(function_call_expression (name) @f (#match? @f \"^(rand|mt_rand|uniqid)$\")) @match",
    },
    message="Use of a predictable PRNG — unsuitable for security purposes.",
    remediation="Use a cryptographic RNG: secrets (Python), crypto.getRandomValues (JS), SecureRandom (Java), getrandom/CSPRNG (C), crypto/rand (Go), random_bytes/random_int (PHP).",
    tags=["security", "cryptography", "weak-random"],
    cwe="CWE-338",
    owasp="A02:2021 Cryptographic Failures"
)

RULES = [AWS_ACCESS_KEY, HARDCODED_SECRET, INSECURE_RAND]
