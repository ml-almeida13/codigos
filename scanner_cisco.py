import nmap  # Biblioteca para escanear a rede

def scan_network_for_cisco(network):
    """
    Escaneia a rede e retorna uma lista de dispositivos Cisco usando detecção de SO.

    :param network: A rede a ser escaneada (ex: '192.168.1.0/24').
    :return: Lista de IPs de dispositivos Cisco.
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-O')  # Ativa a detecção de sistema operacional

    cisco_ips = []
    for host in scanner.all_hosts():
        try:
            if 'cisco' in scanner[host]['osmatch'][0]['name'].lower():
                cisco_ips.append(host)
        except KeyError:
            print(f"Não foi possível identificar o sistema operacional para o host {host}")

    return cisco_ips
