import nmap
import sys


def scan_host(ip, portas="1-1024"):
    scanner = nmap.PortScanner()

    print(f"[*] Iniciando varredura em {ip} (portas {portas})...")

    try:
        # -sV: detecção de versão dos serviços
        # -sC: scripts padrão do Nmap (equivalente a --script=default)
        scanner.scan(ip, portas, arguments="-sV -sC")
    except nmap.PortScannerError as e:
        print(f"[!] Erro ao executar o Nmap: {e}")
        sys.exit(1)

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"Estado: {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"\nProtocolo: {proto}")
            portas_abertas = scanner[host][proto].keys()

            for porta in sorted(portas_abertas):
                info = scanner[host][proto][porta]
                print(f"  Porta {porta}/{proto} - {info['state']}")
                print(f"    Serviço: {info.get('name', 'desconhecido')}")
                print(
                    f"    Versão: {info.get('product', '')} {info.get('version', '')}"
                )

                # resultados dos scripts (-sC)
                if "script" in info:
                    for script_nome, saida in info["script"].items():
                        print(f"    [script:{script_nome}] {saida}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python scanner.py <IP> [portas]")
        sys.exit(1)

    ip_alvo = sys.argv[1]
    portas = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    scan_host(ip_alvo, portas)
