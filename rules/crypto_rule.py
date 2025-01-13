from .base_rule import BaseRule
import re

class CryptographicFailuresRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.severity = "ALTA"
        self.description = "A02:2021 - Cryptographic Failures"
        self.patterns = [
            # Algoritmos débiles
            r"DES\.",
            r"RC4\.",
            r"MD4\.",
            r"MD5\.",
            r"SHA1\.",
            r"ECB mode",
            # Configuraciones inseguras
            r"cipher\.MODE_ECB",
            r"Crypto\.Cipher\.AES\.new\([^,]+\)",  # Sin modo especificado
            r"SSLv2",
            r"SSLv3",
            r"TLSv1_0",
            r"TLSv1_1",
            # Generación de números aleatorios insegura
            r"random\.",
            r"randint\(",
            r"Math\.random\(",
            # Contraseñas y claves débiles
            r"key_size\s*=\s*64",
            r"key_size\s*=\s*128",
            r"iterations\s*=\s*[0-9]{1,3}",  # Pocas iteraciones en derivación de claves
            # Transmisión insegura
            r"http://",
            r"ftp://",
            r"verify\s*=\s*False",
            r"check_hostname\s*=\s*False",
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
                    'description': f"Posible fallo criptográfico detectado"
                }
        return None 