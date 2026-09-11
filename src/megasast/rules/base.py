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
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.severity.upper() not in {"HIGH", "MEDIUM", "LOW", "INFO", "NOTE"}:
            raise ValueError(f"Invalid severity {self.severity}")
