from megasast.rules.base import Rule

# Crypto-hygiene rules: misused primitives detectable by shallow AST
# patterns (credential/secrets exposure detection is deliberately NOT a
# megasast goal — that problem is comprehensively served by dedicated
# secret scanners such as gitleaks, trufflehog, and platform-native
# secret scanning).

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

RULES = [INSECURE_RAND]
