import nmap
import sys

def scan_host(ip, portas="1-1024"):
    scanner = nmap.PortScanner()
    
    print(f"[*] Iniciando varredura em {ip} (portas {portas})...")
    
    try:

        scanner.scan(ip, portas, arguments="-sV -sC")

    except nmap.PortScannerError as e:

        print(f"[!] Erro ao executar o Nmap: {e}")
        sys.exit(1)

    return scanner

def extrat_results(scanner):

    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            portas_abertas = scanner[host][proto].keys()
            for porta in sorted(portas_abertas):

                info = scanner[host][proto][porta]
                
                results.append({
                    "host" : host   
                    "proto" : proto
                    "porta" : porta
                    "estado" : info.get("state", "")
                    "serviço" : info.get ("name" , "unknow")
                    "produto" : info.get("product","")
                    "versao" : info.get ("version" , "")
                    "scripts" : info.get ("script" , {})
                })

    return results

def display_results(results):

    for r in results: 

        print(f" \nPorta {r ["porta"]}/{r["proto"]} - {r['state']}({r["host"]}) ")
        print (f" {r["produto"]} {r["versao"]}")
            for script_nome, saida in info['script'].items():
                print(f"    [script:{script_nome}] {saida}")





    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python scanner.py <IP> [portas]")
        sys.exit(1)

    ip_alvo = sys.argv[1]
    portas = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    scan_host(ip_alvo, portas)


    def ask_auth(porta):
