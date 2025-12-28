import scapy.all as scapy
import argparse
import socket
import sys

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range (e.g. 192.168.1.1/24)", required=True)
    parser.add_argument("-p", "--ports", dest="ports", help="Ports to scan (e.g. 22,80,443 or 1-100)", default=None)
    return parser.parse_args()

def parse_ports(ports_str):
    if not ports_str:
        return []
    ports = []
    if "-" in ports_str:
        start, end = map(int, ports_str.split("-"))
        ports = list(range(start, end + 1))
    elif "," in ports_str:
        ports = list(map(int, ports_str.split(",")))
    else:
        try:
            ports = [int(ports_str)]
        except ValueError:
            print(f"[-] Invalid port format: {ports_str}")
    return ports

def discover_hosts(ip):
    print(f"[+] Scanning {ip} for active hosts...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    try:
        # timeout: wait 1 second for response. verbose: don't print scapy noise
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    except Exception as e:
        print(f"[-] Error sending ARP packets: {e}")
        return []
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def scan_ports(ip, ports):
    print(f"\n[+] Scanning ports on {ip}...")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            print(f"    [+] Port {port} is OPEN")
        sock.close()
    return open_ports

def print_result(results_list):
    print("\n[+] Discovered Hosts:\nIP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

def main():
    options = get_arguments()
    
    # Parse ports
    ports_to_scan = parse_ports(options.ports)

    # Host Discovery
    try:
        scan_result = discover_hosts(options.target)
        if not scan_result:
            print("[-] No hosts found.")
            return

        print_result(scan_result)
        
        # Port Scanning
        if ports_to_scan:
            print("\n[+] Starting Port Scan...")
            for client in scan_result:
                scan_ports(client["ip"], ports_to_scan)
        else:
            print("\n[!] No ports specified for scanning. Use -p to scan ports.")

    except PermissionError:
        print("[-] Error: Permission denied. Please run with sudo.")
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
