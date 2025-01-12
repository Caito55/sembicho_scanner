from .base_rule import BaseRule
import re

class BrokenAuthenticationRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A2:2017 - Broken Authentication"
        self.patterns = [
            # Credenciales hardcodeadas
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"passwd\s*=\s*['\"][^'\"]+['\"]",
            r"pwd\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            # Hashes débiles
            r"md5\s*\(",
            r"sha1\s*\(",
            r"base64\.encode",
            # Configuraciones inseguras
            r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"SECURITY_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"AUTH_KEY\s*=\s*['\"][^'\"]+['\"]",
            # Tokens y sesiones
            r"session\.sign\s*=\s*False",
            r"verify\s*=\s*False",
            r"check_hostname\s*=\s*False",
            # Configuraciones de cookies
            r"secure\s*=\s*False",
            r"httponly\s*=\s*False",
            r"samesite\s*=\s*None",
            # Debugging
            r"DEBUG\s*=\s*True",
            r"DEVELOPMENT_MODE\s*=\s*True",
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