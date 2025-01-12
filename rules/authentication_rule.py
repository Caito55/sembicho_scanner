from .base_rule import BaseRule
import re

class BrokenAuthenticationRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A2:2017 - Broken Authentication"
        self.patterns = [
            r"password\s*=\s*['\"][^'\"]+['\"]",  # Contraseñas hardcodeadas
            r"md5\s*\(",  # Uso de MD5 (hash débil)
            r"sha1\s*\(",  # Uso de SHA1 (hash débil)
            r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",  # Claves secretas hardcodeadas
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
                    'description': "Posible problema de autenticación detectado"
                }
        return None 