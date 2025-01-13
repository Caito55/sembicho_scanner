from .base_rule import BaseRule
import re

class SSRFRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A10:2021 - Server-Side Request Forgery"
        self.patterns = [
            # Peticiones HTTP inseguras
            r"urllib\.request\.urlopen\s*\(",
            r"requests\.(get|post|put|delete)\s*\(",
            r"http\.client\.HTTP(Connection|SConnection)\s*\(",
            r"urllib\.parse\.urljoin\s*\(",
            # Validación de URL insegura
            r"allow_redirects\s*=\s*True",
            r"followRedirect\s*=\s*True",
            r"validate_cert\s*=\s*False",
            # Patrones de frameworks
            r"curl_exec\s*\(",
            r"file_get_contents\s*\(",
            r"\.read_url\s*\(",
            # APIs y servicios web
            r"\.fetch\s*\(",
            r"\.download\s*\(",
            r"\.load_url\s*\(",
            # Configuraciones peligrosas
            r"internal_ips\s*=\s*\[\]",
            r"allowed_hosts\s*=\s*\[\'\*\'\]",
            r"proxy\s*=\s*None",
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
                    'description': f"Posible vulnerabilidad SSRF detectada"
                }
        return None 