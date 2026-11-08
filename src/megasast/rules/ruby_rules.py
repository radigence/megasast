from megasast.rules.base import Rule

# Ruby: the ruby grammar parses method calls as `call` nodes whose first
# children are the receiver (optional) and the method identifier, so
# positional captures avoid depending on field names.

RB_EVAL = Rule(
    id="megasast/ru-eval",
    name="Ruby eval() usage",
    description="eval executes a string as Ruby code; untrusted input reaching it leads to arbitrary code execution.",
    severity="HIGH",
    languages=["ruby"],
    queries={
        "ruby": "(call (identifier) @m (argument_list) (#eq? @m \"eval\")) @match",
    },
    message="Use of eval() — arbitrary code execution risk.",
    remediation="Parse the expected input format instead of evaluating it; restrict dynamic code paths to a strict allow-list.",
    tags=["security", "injection"],
    cwe="CWE-95",
    owasp="A03:2021 Injection"
)

RB_MARSHAL_LOAD = Rule(
    id="megasast/ru-marshal-load",
    name="Ruby Marshal.load usage",
    description="Marshal.load deserializes Ruby object graphs and can lead to arbitrary code execution on untrusted data.",
    severity="HIGH",
    languages=["ruby"],
    queries={
        "ruby": "(call (constant) @recv (identifier) @m (#eq? @recv \"Marshal\") (#match? @m \"^loads?$\")) @match",
    },
    message="Use of Marshal.load/loads() — arbitrary code execution risk.",
    remediation="Do not deserialize untrusted data with Marshal; prefer JSON with schema validation or a data format without executable payloads.",
    tags=["security", "deserialization"],
    cwe="CWE-502",
    owasp="A08:2021 Software and Data Integrity Failures"
)

RULES = [RB_EVAL, RB_MARSHAL_LOAD]
