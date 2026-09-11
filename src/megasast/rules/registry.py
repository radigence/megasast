from megasast.rules.base import Rule
import importlib.metadata as importlib_metadata

def _load_builtin_rules():
    from megasast.rules.python_rules import RULES as PYTHON_RULES
    from megasast.rules.js_rules import RULES as JS_RULES
    from megasast.rules.java_rules import RULES as JAVA_RULES
    from megasast.rules.c_rules import RULES as C_RULES
    from megasast.rules.go_rules import RULES as GO_RULES
    from megasast.rules.php_rules import RULES as PHP_RULES
    return PYTHON_RULES + JS_RULES + JAVA_RULES + C_RULES + GO_RULES + PHP_RULES

def _load_entry_point_rules():
    rules = []
    try:
        for ep in importlib_metadata.entry_points().select(group="megasast.rules"):
            try:
                mod = ep.load()
                # expect module to expose RULES list
                if hasattr(mod, "RULES"):
                    rules.extend(mod.RULES)
            except Exception:
                pass
    except Exception:
        pass
    return rules

RULES = _load_builtin_rules() + _load_entry_point_rules()
