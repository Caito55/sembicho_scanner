from .base_rule import BaseRule
import re

class BrokenAccessControlRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A5:2017 - Broken Access Control"
        self.patterns = [
            # Bypass de autenticación
            r"@login_required\s*=\s*False",
            r"auth\s*=\s*False",
            r"authentication_classes\s*=\s*\[\]",
            r"permission_classes\s*=\s*\[\]",
            # CORS inseguro
            r"Access-Control-Allow-Origin\s*:\s*\*",
            r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
            r"add_header\s*\'Access-Control-Allow-Origin\'\s*\*",
            # Manipulación de IDs
            r"\.get\(.*request\.(GET|POST)\[.*id.*\]\)",
            r"\.filter\(.*request\.(GET|POST)\[.*id.*\]\)",
            # Permisos inseguros
            r"chmod\s+777",
            r"os\.chmod\(.*0o777\)",
            r"ALLOW_ALL_ORIGINS\s*=\s*True",
            # JWT inseguro
            r"verify_signature\s*=\s*False",
            r"check_exp\s*=\s*False",
            r"require_exp\s*=\s*False",
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
                    'description': f"Posible problema de control de acceso detectado"
                }
        return None 