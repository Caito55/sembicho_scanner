from .base_rule import BaseRule
import re

class BusinessLogicRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "Business Logic Vulnerabilities"
        self.patterns = [
            # Race Conditions
            r"\.save\s*\([^)]*commit\s*=\s*False",
            r"\.update\s*\([^)]*\)",
            r"\.delete\s*\([^)]*\)",
            # Validación de transacciones
            r"transaction\.commit\s*\(",
            r"transaction\.rollback\s*\(",
            r"@transaction\.atomic",
            # Mass Assignment
            r"\.objects\.create\s*\([^)]*request\.POST",
            r"\.objects\.update\s*\([^)]*request\.POST",
            r"\.save\s*\([^)]*request\.POST",
            # Límites y restricciones
            r"limit\s*=\s*None",
            r"max_size\s*=\s*None",
            r"timeout\s*=\s*None",
            # Operaciones críticas sin validación
            r"def\s+transfer\s*\([^)]*\)",
            r"def\s+purchase\s*\([^)]*\)",
            r"def\s+delete\s*\([^)]*\)",
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
                    'description': f"Posible vulnerabilidad en la lógica de negocio detectada"
                }
        return None 