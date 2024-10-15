import xml.etree.ElementTree as ET
import nmap
import netifaces

# Função para obter o gateway padrão
def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

# Função para escanear a rede e obter os hosts
def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-A')  # Inclui a detecção de sistema operacional
    hosts_info = []

    for host in nm.all_hosts():
        mac = nm[host]['addresses'].get('mac', 'Desconhecido')
        vendor = nm[host]['vendor'].get(mac, 'Fabricante desconhecido')
        
        # Verifica se há correspondência de sistema operacional
        os_match = nm[host].get('osmatch', [])
        os = os_match[0]['name'] if os_match else 'Desconhecido'  # Usa 'Desconhecido' se não houver correspondência
        
        hosts_info.append({
            'ip': host,
            'mac': mac, 
            'vendor': vendor,
            'os': os  # Adiciona a informação do sistema operacional
        })
    return hosts_info

# Mapeamento de tipos de dispositivos para ícones do Draw.io
def get_device_icon(vendor, os):
    if "Windows" in os:  # Verifica se o sistema operacional é Windows
        return 'shape=mxgraph.cisco.computers_and_peripherals.laptop;'
    elif "Linux" in os or "Android" in os or "iOS" in os:  # Verifica se o sistema operacional é Linux, Android ou iOS
        return 'shape=mxgraph.cisco.modems_and_phones.cell_phone;'
    elif "AP" in vendor or "Access Point" in vendor or "Router" in vendor:  # Adiciona verificação para roteador
        return 'shape=mxgraph.cisco.switches.wireless_access_point;'
    elif "Switch" in vendor:
        return 'shape=mxgraph.cisco.switches.workgroup_switch;'
    elif "PC" in vendor or "Host" in vendor:
        return 'shape=mxgraph.cisco.computers_and_peripherals.pc;'
    else:
        return 'shape=mxgraph.cisco.modems_and_phones.modem;'

# Função para criar um dispositivo (Access Point ou Host) no XML
def create_device(id, ip, mac, fabricante, os, x, y, device_type):
    style = get_device_icon(device_type, os)
    style += 'verticalLabelPosition=bottom;verticalAlign=top;html=1;'  # Adiciona estilo adicional
    
    device = ET.Element('mxCell', {
        'id': id,
        'value': f"<b>{fabricante}</b><br>IP: {ip}<br>MAC: {mac}<br>OS: {os}",  # Inclui a informação do sistema operacional
        'style': style,
        'vertex': '1',
        'parent': '1'
    })
    geometry = ET.SubElement(device, 'mxGeometry', {
        'x': str(x), 'y': str(y), 'width': '101', 'height': '50', 'as': 'geometry'
    })
    return device

# Função para criar uma conexão entre dispositivos no XML
def create_connection(id, source_id, target_id):
    connection = ET.Element('mxCell', {
        'id': id,
        'source': source_id,
        'target': target_id,
        'style': 'edgeStyle=orthogonalEdgeStyle;strokeColor=#FFFFFF;',
        'edge': '1',
        'parent': '1'
    })
    ET.SubElement(connection, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
    return connection

# Função principal para gerar o mapa XML no formato compatível com Draw.io
def generate_network_map(ip_range):
    # Obtém o gateway padrão
    default_gateway = get_default_gateway()
    print(f"Gateway padrão identificado: {default_gateway}")

    hosts = scan_network(ip_range)
    
    # Estrutura básica do arquivo XML do Draw.io
    mxfile = ET.Element('mxfile', host="app.diagrams.net")
    diagram = ET.SubElement(mxfile, 'diagram', name="Network Map")
    
    mxGraphModel = ET.SubElement(diagram, 'mxGraphModel', dx="3680", dy="2493", grid="0", gridSize="10", guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="0",pageScale="1",pageWidth="1920",pageHeight="1200",math="0", shadow="0")
    root = ET.SubElement(mxGraphModel, 'root')
    
    # Elementos de base
    ET.SubElement(root, 'mxCell', id="0")
    ET.SubElement(root, 'mxCell', id="1", parent="0")
    
    # Gerador de IDs únicos
    unique_id = 2

    # Adicionando o Gateway (roteador) ao mapa
    ap =
    ap = create_device(str(unique_id), default_gateway, ap{'mac'},ap{'fabricante'},ap{'os'}, 100, 100, "Router")
    root.append(ap)
    ap_id = str(unique_id)  # Guardar o ID do roteador
    unique_id += 1
    
    # Filtrar hosts que não correspondem ao gateway para evitar duplicação
    hosts = [host for host in hosts if host['ip'] != default_gateway]

    # Adicionando os Hosts encontrados na varredura
    for host in hosts:
        host_id = str(unique_id)
        device = create_device(host_id, host['ip'], host['mac'], host['vendor'], host['os'], 300, 100 + (unique_id - 2) * 100, host['vendor'])  # Adiciona o OS
        root.append(device)
        
        # Conexão entre o Roteador (Gateway) e o Host
        connection = create_connection(str(unique_id + 1000), ap_id, host_id)
        root.append(connection)

        unique_id += 1

    # Gerando o arquivo XML
    tree = ET.ElementTree(mxfile)
    tree.write('network_map.xml', encoding='utf-8', xml_declaration=True)
    print("Mapa da rede gerado com sucesso!")

if __name__ == "__main__":
    ip_range = "192.168.15.0/24"  # Ajuste para o range da sua rede menor
    generate_network_map(ip_range)
