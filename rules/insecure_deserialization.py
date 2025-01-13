from .base_rule import BaseRule
import re

class InsecureDeserializationRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A8:2017 - Insecure Deserialization"
        self.patterns = [
            # Pickle inseguro
            r"pickle\.loads?\s*\(",
            r"cPickle\.loads?\s*\(",
            r"marshal\.loads?\s*\(",
            # YAML inseguro
            r"yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"yaml\.full_load\s*\(",
            # JSON inseguro
            r"json\.loads?\s*\(.*verify\s*=\s*False",
            r"jsonpickle\.decode\s*\(",
            r"simplejson\.loads?\s*\(",
            # Deserialización personalizada
            r"__setstate__\s*\(",
            r"__getstate__\s*\(",
            r"ObjectMapper\.readValue\s*\(",
            # Otros formatos
            r"shelve\.open\s*\(",
            r"dill\.loads?\s*\(",
            r"joblib\.load\s*\(",
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
                    'description': f"Posible deserialización insegura detectada"
                }
        return None 