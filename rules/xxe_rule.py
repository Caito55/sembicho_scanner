from .base_rule import BaseRule
import re

class XXERule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A4:2017 - XML External Entities (XXE)"
        self.patterns = [
            # Parsers XML vulnerables
            r"xml\.etree\.ElementTree\.parse\s*\(",
            r"xml\.dom\.minidom\.parse\s*\(",
            r"xml\.sax\.parse\s*\(",
            r"xmlrpclib\.ServerProxy\s*\(",
            r"lxml\.etree\.parse\s*\(",
            # Configuraciones inseguras de XML
            r"resolve_entities\s*=\s*True",
            r"no_network\s*=\s*False",
            r"dtd_validation\s*=\s*True",
            r"XMLParser\s*\([^)]*external_dtd",
            r"\.setFeature\(.*EXTERNAL_GENERAL_ENTITIES.*true\)",
            # Patrones de SOAP vulnerables
            r"suds\.client\.Client\s*\(",
            r"zeep\.Client\s*\(",
            r"from\s+defusedxml\s+import",
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
                    'description': f"Posible vulnerabilidad XXE detectada"
                }
        return None 