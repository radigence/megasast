from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW
    languages: List[str]
    queries: Dict[str, str]
    message: str
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None

    def __post_init__(self):
        # Only severities the product surface actually supports: the CLI's
        # --severity/--fail-on choices and the SARIF error/warning/note
        # mapping cover HIGH/MEDIUM/LOW. If INFO or NOTE severities are
        # introduced, extend the CLI choices and the SARIF level mapping too.
        if self.severity.upper() not in {"HIGH", "MEDIUM", "LOW"}:
            raise ValueError(f"Invalid severity {self.severity}")
