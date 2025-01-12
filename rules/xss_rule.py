from .base_rule import BaseRule
import re

class XSSRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A7:2017 - Cross-Site Scripting (XSS)"
        self.patterns = [
            r"render_template_string\s*\(\s*.*\+",
            r"\.html\s*\(\s*.*\+",
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"\.html\s*\(",
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
                    'description': f"Posible vulnerabilidad XSS detectada"
                }
        return None
    