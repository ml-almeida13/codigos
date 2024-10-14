## CHAT GTP

from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Cria o pacote ARP de solicitação
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Envia pacotes e recebe as respostas
    result = srp(packet, timeout=2, verbose=0)[0]

    # Processa as respostas para pegar IP e MAC
    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return hosts

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"  # Substitua pelo range da sua rede
    hosts = scan_network(ip_range)
    print("Dispositivos encontrados:")
    for host in hosts:
        print(f"IP: {host['ip']}, MAC: {host['mac']}")
