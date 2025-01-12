from .base_rule import BaseRule
import re

class SQLInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A1:2017 - Inyección SQL"
        self.patterns = [
            # Patrones básicos de SQL
            r"SELECT.*WHERE.*=.*\+",
            r"INSERT.*VALUES.*\+",
            r"UPDATE.*SET.*=.*\+",
            r"DELETE.*FROM.*WHERE.*\+",
            # Patrones de ORM y frameworks
            r"raw_query\s*\(",
            r"execute\s*\([^)]*\+",
            r"executemany\s*\(",
            r"cursor\.execute",
            r"db\.execute",
            # Patrones de string formatting
            r"\.format.*SELECT",
            r"%\s*SELECT",
            r"f['\"]\s*SELECT",
            # Patrones específicos de frameworks
            r"Model\.objects\.raw",
            r"\.filter\(.*__contains",
            r"\.where\(.*\+",
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
                    'description': f"Posible inyección SQL detectada"
                }
        return None

class CommandInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A1:2017 - Inyección de Comandos"
        self.patterns = [
            # Ejecución de comandos
            r"os\.(system|popen|spawn|exec)\s*\(",
            r"subprocess\.(call|run|Popen|check_output)",
            r"exec\s*\(",
            r"eval\s*\(",
            # Shell commands
            r"shell\s*=\s*True",
            r"commands\.getoutput",
            r"commands\.getstatusoutput",
            r"\.communicate\s*\(",
            # Python specific
            r"__import__\s*\(",
            r"globals\s*\(\s*\)\s*\[",
            r"locals\s*\(\s*\)\s*\[",
            # String formatting en comandos
            r"f['\"]\s*.*\s*`",
            r"\.format.*`",
            r"%.*`",
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
                    'description': f"Posible inyección de comandos detectada"
                }
        return None
    