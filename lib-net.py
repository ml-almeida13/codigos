import netifaces as net

interfaces = net.interfaces()

for interface in interfaces:
    print(f"Nome da interface: {interface}")
    enderecos = net.ifaddresses(interface).get(net.AF_INET, [{}])
    ip = enderecos[0].get('addr', 'N/A')
    mascara = enderecos[0].get('netmask', 'N/A')
    print(f"IP da interface: {ip}")
    print(f"Máscara da interface: {mascara}")

gateways = net.gateways().get('default', {}).get(net.AF_INET, ['N/A'])[0]
print(f"Gateway: {gateways}")
