from .base_rule import BaseRule
import re

class VulnerableComponentsRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A9:2017 - Using Components with Known Vulnerabilities"
        self.patterns = [
            # Versiones específicas vulnerables
            r"django==1\.[0-9]\.",
            r"flask==0\.",
            r"requests==1\.",
            r"urllib3==1\.[0-2][0-9]\.",
            # Comentarios sobre versiones
            r"#.*version.*[<=>]=\s*[0-9]+\.[0-9]+\.[0-9]+",
            r"#.*dependency.*[<=>]=\s*[0-9]+\.[0-9]+\.[0-9]+",
            # Requirements.txt
            r"^[a-zA-Z0-9-_]+==\d+\.\d+\.\d+$",
            # Package.json
            r"\"version\"\s*:\s*\"[~^]?[0-9]+\.[0-9]+\.[0-9]+\"",
            # Importaciones de módulos obsoletos
            r"from\s+urllib2\s+import",
            r"from\s+urllib\s+import",
            r"import\s+md5",
            r"import\s+sha",
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
                    'description': f"Posible uso de componente vulnerable detectado"
                }
        return None 