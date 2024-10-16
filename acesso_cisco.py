from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import nmap  # Biblioteca para escanear a rede

def scan_network(network):
    """
    Escaneia a rede e retorna uma lista de dispositivos Cisco.

    :param network: A rede a ser escaneada (ex: '192.168.1.0/24').
    :return: Lista de IPs de dispositivos Cisco.
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-p 22,23')  # Portas comuns para SSH e Telnet

    cisco_ips = []
    for host in scanner.all_hosts():
        # Verifica se o dispositivo é Cisco
        if 'cisco' in scanner[host]['osmatch'][0].lower():  # Adapte conforme necessário
            cisco_ips.append(host)

    return cisco_ips

def access_cisco_switch(ip, users, passwords):
    """
    Acessa um switch Cisco via SSH ou Telnet usando múltiplas opções de usuários e senhas e retorna o hostname.

    :param ip: Endereço IP do switch.
    :param users: Lista de nomes de usuários para autenticação.
    :param passwords: Lista de senhas para autenticação.
    :return: O hostname do switch ou uma mensagem de erro.
    """
    # Configurações do dispositivo para SSH
    ssh_device = {
        'device_type': 'cisco_ios',  # Tipo de dispositivo para SSH
        'host': ip,
    }

    # Configurações do dispositivo para Telnet
    telnet_device = {
        'device_type': 'cisco_ios_telnet',  # Tipo de dispositivo para Telnet
        'host': ip,
    }

    for user in users:
        for password in passwords:
            ssh_device['username'] = user
            ssh_device['password'] = password
            telnet_device['username'] = user
            telnet_device['password'] = password

            # Tentar conexão via SSH
            try:
                connection = ConnectHandler(**ssh_device)
                hostname = connection.send_command("show running-config | include hostname")
                connection.disconnect()
                return f"Hostname do switch {ip}: {hostname.strip()}"

            except NetmikoAuthenticationException:
                return f"Erro de autenticação ao acessar o switch {ip} com {user}:{password}."

            except NetmikoTimeoutException:
                print(f"Timeout ao conectar via SSH com {user}:{password}. Tentando Telnet...")

                # Tentar conexão via Telnet
                try:
                    connection = ConnectHandler(**telnet_device)
                    hostname = connection.send_command("show running-config | include hostname")
                    connection.disconnect()
                    return f"Hostname do switch {ip}: {hostname.strip()}"

                except NetmikoAuthenticationException:
                    return f"Erro de autenticação ao acessar o switch {ip} com {user}:{password}."

                except NetmikoTimeoutException:
                    return f"Timeout ao acessar o switch via Telnet com {user}:{password}."

    return f"Todas as combinações de usuários e senhas falharam para o switch {ip}."

# Exemplo de uso
if __name__ == "__main__":
    network_to_scan = '10.52.100.0/24'  # Rede a ser escaneada
    users = ['admciscogapgl', 'admciscogapgl', 'Cisco']  # Lista de nomes de usuários
    passwords = ['Cisc0g@pgl', 'ciscogapgl', 'Cisco']  # Lista de senhas

    # Escanear a rede e obter os IPs dos dispositivos Cisco
    cisco_ips = scan_network(network_to_scan)

    # Acessar cada dispositivo Cisco encontrado
    for ip_switch in cisco_ips:
        result = access_cisco_switch(ip_switch, users, passwords)
        print(result)
