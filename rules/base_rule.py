from abc import ABC, abstractmethod

class BaseRule(ABC):
    def __init__(self):
        self.severity = "MEDIA"
        self.description = "Regla base"
        self.patterns = []
    
    @abstractmethod
    def analyze(self, line: str, file_path: str, line_number: int) -> dict:
        """
        Analiza una línea de código en busca de vulnerabilidades
        Retorna None si no hay vulnerabilidad, o un diccionario con la información si la encuentra
        """
        pass
    