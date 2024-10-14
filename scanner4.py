import xml.etree.ElementTree as ET
import nmap

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
        return 'shape=mxgraph.cisco.computers_and_peripherals.laptop;sketch=0;html=1;pointerEvents=1;dashed=0;fillColor=#036897;strokeColor=#ffffff;strokeWidth=2;verticalLabelPosition=bottom;verticalAlign=top;align=center;outlineConnect=0;'
    elif "Linux" in os or "Android" in os or "iOS" in os:  # Verifica se o sistema operacional é Linux, Android ou iOS
        return 'shape=mxgraph.cisco.modems_and_phones.cell_phone;sketch=0;html=1;pointerEvents=1;dashed=0;fillColor=#036897;strokeColor=#ffffff;strokeWidth=2;verticalLabelPosition=bottom;verticalAlign=top;align=center;outlineConnect=0;'
    elif "AP" in vendor or "Access Point" in vendor:
        return 'shape=mxgraph.cisco.switches.wireless_access_point;'
    elif "Switch" in vendor:
        return 'shape=mxgraph.cisco.switches.workgroup_switch;'
    elif "Router" in vendor:
        return 'shape=mxgraph.cisco.routers.router;'
    elif "PC" in vendor or "Host" in vendor:
        return 'shape=mxgraph.cisco.computers_and_peripherals.pc;'
    else:
        return 'shape=mxgraph.cisco.modems_and_phones.modem;sketch=0;html=1;pointerEvents=1;dashed=0;fillColor=#036897;strokeColor=#ffffff;strokeWidth=2;verticalLabelPosition=bottom;verticalAlign=top;align=center;outlineConnect=0;'

# Função para criar um dispositivo (Access Point ou Host) no XML
def create_device(id, ip, mac, fabricante, os, x, y, device_type):
    style = get_device_icon(device_type, os)  # Passa o sistema operacional para a função de estilo
    style += 'verticalLabelPosition=bottom;verticalAlign=top;html=1;'  # Adiciona estilo adicional
    
    # Ajuste as dimensões para que sejam iguais às do conector
    device = ET.Element('mxCell', {
        'id': id,
        'value': f"<b>{fabricante}</b><br>IP: {ip}<br>MAC: {mac}<br>OS: {os}",  # Inclui a informação do sistema operacional
        'style': style,
        'vertex': '1',
        'parent': '1'
    })
    geometry = ET.SubElement(device, 'mxGeometry', {
        'x': str(x), 'y': str(y), 'width': '101', 'height': '50', 'as': 'geometry'  # Ajuste de largura e altura
    })
    return device

# Função para criar uma conexão entre dispositivos no XML
def create_connection(id, source_id, target_id):
    connection = ET.Element('mxCell', {
        'id': id,
        'source': source_id,
        'target': target_id,
        'style': 'edgeStyle=orthogonalEdgeStyle;strokeColor=#FFFFFF;',  # Linha branca
        'edge': '1',
        'parent': '1'
    })
    ET.SubElement(connection, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
    return connection

# Função principal para gerar o mapa XML no formato compatível com Draw.io
def generate_network_map(ip_range):
    hosts = scan_network(ip_range)
    
    # Estrutura básica do arquivo XML do Draw.io
    mxfile = ET.Element('mxfile', host="app.diagrams.net")
    diagram = ET.SubElement(mxfile, 'diagram', name="Network Map")
    
    mxGraphModel = ET.SubElement(diagram, 'mxGraphModel', dx="3680", dy="2493", grid="0", gridSize="10", guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="0",pageScale="1",pageWidth="1920",pageHeight="1200",math="0", shadow="0")
    root = ET.SubElement(mxGraphModel, 'root')
    
    #Elementos de base
    ET.SubElement(root, 'mxCell', id="0")
    ET.SubElement(root, 'mxCell', id="1", parent="0")
    
    # Gerador de IDs únicos
    unique_id = 2  # Começa a partir de 2 porque 0 e 1 já são usados

    # Adicionando o Access Point (exemplo)
    ap = create_device(str(unique_id), "192.168.1.1", "00:11:22:33:44:55", "Access Point", "Desconhecido", 100, 100, "Access Point")
    root.append(ap)
    ap_id = str(unique_id)  # Guardar o ID do AP
    unique_id += 1
    
    # Adicionando os Hosts encontrados na varredura
    for host in hosts:
        host_id = str(unique_id)
        device = create_device(host_id, host['ip'], host['mac'], host['vendor'], host['os'], 300, 100 + (unique_id - 2) * 100, host['vendor'])  # Adiciona o OS
        root.append(device)
        
        # Conexão entre o Access Point e o Host
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
