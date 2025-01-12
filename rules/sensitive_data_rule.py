from .base_rule import BaseRule
import re

class SensitiveDataRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A3:2017 - Exposición de Datos Sensibles"
        self.patterns = [
            # Información personal
            r"social_security\s*=",
            r"ssn\s*=",
            r"credit_card\s*=",
            r"card_number\s*=",
            # Tokens y claves
            r"private_key\s*=",
            r"aws_secret\s*=",
            r"aws_key\s*=",
            r"access_token\s*=",
            # Configuraciones de base de datos
            r"database_url\s*=",
            r"db_password\s*=",
            r"connection_string\s*=",
            # Logging inseguro
            r"print\s*\(\s*password",
            r"console\.log\s*\(\s*password",
            r"logger\.debug\s*\(\s*password",
            # Comentarios con información sensible
            r"#.*password",
            r"//.*password",
            r"/\*.*password.*\*/",
        ]

    def analyze(self, line: str, file_path: str, line_number: int) -> dict:
        for pattern in self.patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return {
                    'file': file_path,
                    'line_number': line_number,
                    'line_content': line.strip(),
                    'rule': self.description,
                    'severity': self.severity,
                    'description': f"Posible exposición de datos sensibles detectada"
                }
        return None 