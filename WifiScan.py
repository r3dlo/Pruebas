import nmap # type: ignore

def scan_network(network):
    #Crear un objeto de escaneo
    nm = nmap.PortScanner()

    print(f"Escaneando la red: {network}...")

    # Escanear la red usando nmap

    nm.scan(hosts=network,arguments='-O') # -O para detección de sistemas operativos

    # Recopilar informaicón 
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print (f"Estado: {nm[host].state()}")

        if 'osmatch' in nm[host]:
            print(f"SO: {nm[host]['osmatch'][0]['name']}")

        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                    print(f"Puerto: {port}, Estado: {nm[host]['tcp'][port]['state']}")
                
        if 'udp' in nm[host]:
            for port in nm[host]['udp']:
                print(f"Puerto: {port}, Estado: {nm[host]['udp'][port]['state']}")

if __name__ == "__main__":
    # Define tu red local. Por ejemplo, "192.168.1.0/24" o "192.168.0.0/24"
    network = "192.168.1.0/24"
    scan_network(network)