#This Python script scans a network to find active devices and attempts to fingerprint them by retrieving their MAC address vendor and checking for open ports.

from scapy.all import ARP, Ether, srp
import socket
import requests


def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"
    except requests.RequestException:
        return "Unknown Vendor"


def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc)
        })
    
    return devices


def scan_ports(ip, ports=[22, 80, 443, 3389]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def main():
    network = "192.168.1.0/24"  # Change to your network range
    print(f"Scanning network: {network}\n")
    devices = scan_network(network)
    
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")
        open_ports = scan_ports(device['ip'])
        if open_ports:
            print(f"  Open ports: {', '.join(map(str, open_ports))}")
        else:
            print("  No common ports open.")
        print("-")

if __name__ == "__main__":
    main()
