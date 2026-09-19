from megasast.rules.base import Rule
from megasast.rules.registry import RULES, ineffective_predicate_warnings


def _rule(queries):
    return Rule(
        id="megasast/test-guard",
        name="guard test",
        description="guard test",
        severity="MEDIUM",
        languages=list(queries),
        queries=queries,
        message="guard test",
    )


def test_single_capture_match_predicate_is_flagged():
    rule = _rule({"c": '(string_literal) @s (#match? @s "AKIA[0-9A-Z]{16}")'})
    warnings = ineffective_predicate_warnings(rule)
    assert len(warnings) == 1
    assert "megasast/test-guard" in warnings[0]
    assert "#match?" in warnings[0] or "match?" in warnings[0]


def test_single_capture_eq_predicate_is_flagged():
    rule = _rule({"c": '(string_literal) @s (#eq? @s "\\"zzz\\"")'})
    assert len(ineffective_predicate_warnings(rule)) == 1


def test_multi_capture_predicate_is_clean():
    rule = _rule({
        "c": '(call_expression function: (identifier) @f (#eq? @f "rand")) @match',
        "java": '(method_invocation object: (identifier) @c name: (identifier) @m '
                'arguments: (argument_list (string_literal) @a) (#eq? @c "Cipher") '
                '(#eq? @m "getInstance") (#match? @a "\\"(DES|RC4|Blowfish)")) @match',
    })
    assert ineffective_predicate_warnings(rule) == []


def test_single_capture_without_predicate_is_clean():
    rule = _rule({"c": "(comment) @match"})
    assert ineffective_predicate_warnings(rule) == []


def test_multi_pattern_flags_only_bad_part():
    rule = _rule({
        "go": '(interpreted_string_literal) @match (#match? @match "x"); '
              '(import_spec path: (interpreted_string_literal) @path (#eq? @path "\\"unsafe\\"")) @match',
    })
    warnings = ineffective_predicate_warnings(rule)
    assert len(warnings) == 1
    assert "go" in warnings[0]


def test_at_sign_inside_string_is_not_a_capture():
    rule = _rule({"c": '(call_expression function: (identifier) @f (#match? @f "a@b")) @match'})
    assert ineffective_predicate_warnings(rule) == []


def test_no_builtin_rule_has_ineffective_predicates():
    bad = {
        rule.id: ineffective_predicate_warnings(rule)
        for rule in RULES
    }
    bad = {rule_id: w for rule_id, w in bad.items() if w}
    assert not bad, f"rules with ineffective predicates: {bad}"
