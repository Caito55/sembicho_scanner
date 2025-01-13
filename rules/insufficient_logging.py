from .base_rule import BaseRule
import re

class InsufficientLoggingRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "MEDIA"
        self.description = "A10:2017 - Insufficient Logging & Monitoring"
        self.patterns = [
            # Desactivación de logs
            r"logging\.disable\s*\(",
            r"log_level\s*=\s*('|\")(CRITICAL|ERROR)",
            r"LOGGING_ENABLED\s*=\s*False",
            # Logs inseguros
            r"print\s*\(\s*exception",
            r"traceback\.print_exc\s*\(",
            r"sys\.exc_info\s*\(",
            # Configuraciones de log inseguras
            r"LOG_LEVEL\s*=\s*('|\")DEBUG",
            r"LOG_TO_STDOUT\s*=\s*True",
            r"LOG_TO_FILE\s*=\s*False",
            # Ausencia de logs en operaciones críticas
            r"@login_required.*\n\s*def\s+.*\(.*\):\s*(?!.*log)",
            r"@admin_required.*\n\s*def\s+.*\(.*\):\s*(?!.*log)",
            r"def\s+delete_.*\(.*\):\s*(?!.*log)",
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
                    'description': f"Posible problema de logging insuficiente detectado"
                }
        return None 