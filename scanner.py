import os
from rules.injection_rule import SQLInjectionRule, CommandInjectionRule
from rules.xss_rule import XSSRule
from rules.authentication_rule import BrokenAuthenticationRule
from rules.sensitive_data_rule import SensitiveDataRule
from rules.xxe_rule import XXERule
from rules.broken_access_control import BrokenAccessControlRule
from rules.security_misconfiguration import SecurityMisconfigurationRule
from rules.insecure_deserialization import InsecureDeserializationRule
from rules.vulnerable_components import VulnerableComponentsRule
from rules.insufficient_logging import InsufficientLoggingRule
from rules.crypto_rule import CryptographicFailuresRule
from rules.server_side_request_forgery import SSRFRule
from rules.api_security_rule import APISecurityRule
from rules.business_logic_rule import BusinessLogicRule

class SecurityScanner:
    def __init__(self):
        self.rules = [
            SQLInjectionRule(),
            CommandInjectionRule(),
            XSSRule(),
            BrokenAuthenticationRule(),
            SensitiveDataRule(),
            XXERule(),
            BrokenAccessControlRule(),
            SecurityMisconfigurationRule(),
            InsecureDeserializationRule(),
            VulnerableComponentsRule(),
            InsufficientLoggingRule(),
            CryptographicFailuresRule(),
            SSRFRule(),
            APISecurityRule(),
            BusinessLogicRule(),
        ]

    def scan(self, path):
        vulnerabilities = []
        
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.py', '.js', '.php', '.html', '.jsx', '.tsx')):
                    file_path = os.path.join(root, file)
                    file_vulns = self._scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
        
        return vulnerabilities

    def _scan_file(self, file_path):
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines, 1):
                for rule in self.rules:
                    result = rule.analyze(line, file_path, i)
                    if result:
                        vulnerabilities.append(result)
        except Exception as e:
            print(f"Error al escanear {file_path}: {str(e)}")
        
        return vulnerabilities
