import nmap

## criar uma função que faço o escaner na rede

def scanner_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-A')
    hosts_info=[]
    print(f"Dispositivos encontrados: \n")
    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac','Desconhecido')
        print(f'IP:{host}\n MAC:{mac}\n')
