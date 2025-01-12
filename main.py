import sys
from scanner import SecurityScanner

def main():
    if len(sys.argv) != 2:
        print("Uso: python main.py <ruta_a_analizar>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    scanner = SecurityScanner()
    vulnerabilities = scanner.scan(target_path)
    
    # Guardar resultados en el reporte
    with open('report.txt', 'w', encoding='utf-8') as f:
        if vulnerabilities:
            f.write("=== Reporte de Vulnerabilidades ===\n\n")
            for vuln in vulnerabilities:
                f.write(f"Archivo: {vuln['file']}\n")
                f.write(f"Línea: {vuln['line_number']}\n")
                f.write(f"Regla: {vuln['rule']}\n")
                f.write(f"Descripción: {vuln['description']}\n")
                f.write("-" * 50 + "\n")
        else:
            f.write("No se encontraron vulnerabilidades.")

if __name__ == "__main__":
    main()
