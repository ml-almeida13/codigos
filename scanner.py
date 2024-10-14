# Projeto para scanner hosts na rede e retornar o nome dos fabricantes com base no OUI
import ouilookup as oui

from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
#
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append({'ip':received.psrc,'mac':received.hwsrc})

    return hosts

def get_manufacturer(mac_address):
    try:
        mac = oui.get_manufacturer(mac_address)
    except Exception:
        mac = 'Fabricante desconhecido'
    return mac

if __name__ == "__main__":
    ip_range = "192.168.15.0/24"
    hosts = scan_network(ip_range)
    print("Dispositivos encontrados")
    for host in hosts:
        manufacturer =  get_manufacturer(host['mac'])
        print(f"IP: {host['ip']}\nMAC: {host['mac']}\n Fabricante: {manufacturer}\n")    

