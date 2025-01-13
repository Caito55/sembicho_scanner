from .base_rule import BaseRule
import re

class APISecurityRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "API Security Vulnerabilities"
        self.patterns = [
            # Rate Limiting ausente
            r"@ratelimit\([^)]*none[^)]*\)",
            r"RATELIMIT_ENABLED\s*=\s*False",
            r"throttle_classes\s*=\s*\[\]",
            # Validación de entrada
            r"@validate\s*=\s*False",
            r"validation\s*=\s*False",
            r"sanitize\s*=\s*False",
            # Exposición de información
            r"@api_view\([^)]*\)",
            r"\.all\(\)",
            r"\.raw\(\)",
            # Manejo de errores inseguro
            r"catch\s*\([^)]*\)\s*{\s*console\.log",
            r"except\s*Exception\s*as\s*e:\s*print",
            r"DEBUG\s*=\s*True",
            # Seguridad de endpoints
            r"@csrf_exempt",
            r"@require_http_methods\([^)]*\)",
            r"@public",
            # Configuraciones inseguras
            r"REST_FRAMEWORK\s*=\s*\{[^}]*'DEFAULT_AUTHENTICATION_CLASSES'\s*:\s*\[\][^}]*\}",
            r"REST_FRAMEWORK\s*=\s*\{[^}]*'DEFAULT_PERMISSION_CLASSES'\s*:\s*\[\][^}]*\}",
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
                    'description': f"Posible vulnerabilidad de seguridad en API detectada"
                }
        return None 