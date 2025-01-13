from .base_rule import BaseRule
import re

class SecurityMisconfigurationRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A6:2017 - Security Misconfiguration"
        self.patterns = [
            # Configuraciones de desarrollo
            r"DEBUG\s*=\s*True",
            r"DEVELOPMENT_MODE\s*=\s*True",
            r"TESTING\s*=\s*True",
            # Headers de seguridad faltantes
            r"X-Frame-Options\s*:\s*ALLOW",
            r"X-Content-Type-Options\s*:\s*none",
            r"SECURE_HSTS_SECONDS\s*=\s*0",
            # Configuraciones de cookies inseguras
            r"SESSION_COOKIE_SECURE\s*=\s*False",
            r"CSRF_COOKIE_SECURE\s*=\s*False",
            r"SECURE_SSL_REDIRECT\s*=\s*False",
            # Exposición de información
            r"SHOW_ERROR_DETAILS\s*=\s*True",
            r"DISPLAY_DEBUG_TOOLBAR\s*=\s*True",
            r"EXPOSE_HEADERS\s*=\s*True",
            # Configuraciones de caché inseguras
            r"CACHE_TTL\s*=\s*0",
            r"NO_CACHE\s*=\s*True",
            r"Cache-Control\s*:\s*no-store",
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
                    'description': f"Posible error de configuración de seguridad detectado"
                }
        return None 