import sys
import os
import json
from datetime import datetime
from scanner import SecurityScanner

def generate_json_report(vulnerabilities, target_path, output_path):
    report = {
        "scan_info": {
            "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "directorio_analizado": target_path,
            "total_vulnerabilidades": len(vulnerabilities)
        },
        "resumen": {
            "alta": sum(1 for v in vulnerabilities if v['severity'] == "ALTA"),
            "media": sum(1 for v in vulnerabilities if v['severity'] == "MEDIA"),
            "baja": sum(1 for v in vulnerabilities if v['severity'] == "BAJA")
        },
        "vulnerabilidades": {
            "alta": [v for v in vulnerabilities if v['severity'] == "ALTA"],
            "media": [v for v in vulnerabilities if v['severity'] == "MEDIA"],
            "baja": [v for v in vulnerabilities if v['severity'] == "BAJA"]
        }
    }
    
    json_path = os.path.join(output_path, 'report.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    
    return json_path

def main():
    if len(sys.argv) != 2:
        print("Uso: python main.py <ruta_a_analizar>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    scanner = SecurityScanner()
    vulnerabilities = scanner.scan(target_path)
    
    output_dir = os.getcwd()
    json_path = generate_json_report(vulnerabilities, target_path, output_dir)
    
    print(f"\nReporte JSON generado en: {json_path}")

if __name__ == "__main__":
    main()
