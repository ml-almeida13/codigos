import nmap
import ouilookup
import netifaces as net

# Função para identificar o fabricante com ouilookup
def get_manufacturer(mac):
    try:
        # Extrai os primeiros 6 dígitos do MAC (OUI) e faz a busca
        oui = mac[:8].upper()  # Extrai o OUI (3 primeiros octetos do MAC)
        return ouilookup.get_manufacturer(oui)
    except Exception:
        return "Fabricante desconhecido"

# Função para escanear a rede e obter os hosts
def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-O')
    hosts_info = []

    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'Desconhecido')
        vendor = nm[host]['vendor'].get(mac, 'Fabricante desconhecido')

        # Se o fabricante for "Desconhecido", usa a biblioteca ouilookup
        if vendor == "Fabricante desconhecido" and mac != 'Desconhecido':
            vendor = get_manufacturer(mac)

        hosts_info.append({
            'ip': host,
            'mac': mac, 
            'vendor': vendor
        })
    return hosts_info

if __name__ == "__main__":
    ip_range = "192.168.15.0/24"
    hosts = scan_network(ip_range)

    print("Dispositivos encontrados:")
    for host in hosts:
        print(f"IP: {host['ip']},\n MAC: {host['mac']},\n Fabricante: {host['vendor']}\n")

    # Exibe a quantidade de dispositivos encontrados
    print(f"Quantidade de dispositivos encontrados: {len(hosts)}")
