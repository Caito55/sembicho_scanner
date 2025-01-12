from .base_rule import BaseRule
import re

class XSSRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A7:2017 - Cross-Site Scripting (XSS)"
        self.patterns = [
            # Patrones básicos de XSS
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"document\.write\s*\(",
            r"\.html\s*\(",
            # Frameworks específicos
            r"dangerouslySetInnerHTML",
            r"v-html=",
            r"\[innerHTML\]",
            # Template engines
            r"render_template_string",
            r"mark_safe",
            r"safe\s*\|",
            r"\|\s*safe",
            # Sanitización insegura
            r"sanitize_html",
            r"bypass_sanitize",
            # DOM manipulation
            r"\.insertAdjacentHTML",
            r"\.createHTML",
            r"\.parseHTML",
            # Eventos peligrosos
            r"eval\s*\(",
            r"setTimeout\s*\(\s*['\"]",
            r"setInterval\s*\(\s*['\"]",
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
    