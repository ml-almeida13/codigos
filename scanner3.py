import xml.etree.ElementTree as ET
import nmap

# Função para escanear a rede e obter os hosts
def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-O')
    hosts_info = []

    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'Desconhecido')
        vendor = nm[host]['vendor'].get(mac, 'Fabricante desconhecido')
        hosts_info.append({
            'ip': host,
            'mac': mac, 
            'vendor': vendor
        })
    return hosts_info

# Mapeamento de tipos de dispositivos para ícones do Draw.io
def get_device_icon(vendor):
    if "AP" in vendor or "Access Point" in vendor:
        return 'shape=mxgraph.cisco.switches.wireless_access_point;'
    elif "Switch" in vendor:
        return 'shape=mxgraph.cisco.switches.workgroup_switch;'
    elif "Router" in vendor:
        return 'shape=mxgraph.cisco.routers.router;'
    elif "PC" in vendor or "Host" in vendor:
        return 'shape=mxgraph.cisco.computers_and_peripherals.pc;'
    else:
        return 'shape=mxgraph.cisco.switches.generic_host;'  # Ícone genérico para outros dispositivos

# Função para criar um dispositivo (Access Point ou Host) no XML
def create_device(id, ip, mac, fabricante, x, y, device_type):
    style = get_device_icon(device_type)
    style += 'verticalLabelPosition=bottom;verticalAlign=top;html=1;strokeColor=#000000;fillColor=#ffffff;'
    
    device = ET.Element('mxCell', {
        'id': id,
        'value': f"<b>{fabricante}</b><br>IP: {ip}<br>MAC: {mac}",
        'style': style,
        'vertex': '1',
        'parent': '1'
    })
    
