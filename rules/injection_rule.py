from .base_rule import BaseRule
import re

class SQLInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A1:2017 - Inyección SQL"
        self.patterns = [
            r"SELECT.*WHERE.*\=\s*['\"]\s*\+",
            r"SELECT.*WHERE.*\=\s*\%s",
            r"execute\s*\(\s*[\"'].*\+",
            r"cursor\.execute\s*\(\s*[\"'].*\+",
            r"raw_input\s*\(\s*.*SELECT",
        ]

class CommandInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A1:2017 - Inyección de Comandos"
        self.patterns = [
            r"os\.system\s*\(\s*[\"'].*\+",
            r"subprocess\.call\s*\(\s*[\"'].*\+",
            r"exec\s*\(\s*[\"'].*\+",
            r"eval\s*\(",
        ]

    def analyze(self, line: str, file_path: str, line_number: int) -> dict:
        for pattern in self.patterns:
            if re.search(pattern, line):
                return {
                    'file': file_path,
                    'line_number': line_number,
                    'line_content': line.strip(),
                    'rule': self.description,
                    'severity': self.severity,
                    'description': f"Posible inyección de comandos detectada"
                }
        return None
    