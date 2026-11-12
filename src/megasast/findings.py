from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    snippet: str
    severity: str
