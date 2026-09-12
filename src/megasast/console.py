import json


BANNER = r"""
 __  __ _____ ____    _    ____    _    ____ _____
|  \/  | ____/ ___|  / \  / ___|  / \  / ___|_   _|
| |\/| |  _|| |  _  / _ \ \___ \ / _ \ \___ \ | |
| |  | | |__| |_| |/ ___ \ ___) / ___ \ ___) || |
|_|  |_|_____\____/_/   \_\____/_/   \_\____/ |_|
""".strip()


def print_banner():
    print(BANNER)

def print_summary(findings):
    if not findings:
        print("No findings.")
        return
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, 0)
        by_rule[f.rule_id] += 1
    print(f"Total findings: {len(findings)}")
    for rid, count in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"  {rid}: {count}")
