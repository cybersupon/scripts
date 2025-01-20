import scapy.all as scapy
import socket
import requests
import threading
import subprocess
import sys
import os
from queue import Queue

# Function to create a virtual environment and install dependencies
def setup_venv():
    venv_dir = "venv"
    if not os.path.exists(venv_dir):
        print("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])

    pip_path = os.path.join(venv_dir, "scripts", "pip.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "pip")

    print("Installing dependencies in virtual environment...")
    dependencies = ["scapy", "requests"]
    for dependency in dependencies:
        try:
            subprocess.check_call([pip_path, "install", dependency])
        except subprocess.CalledProcessError:
            print(f"Failed to install {dependency}. Please install it manually.")
            sys.exit(1)

    print("Virtual environment setup complete. Activate it before running the script.")
    print(f"Activate command: {'venv\\scripts\\activate' if os.name == 'nt' else 'source venv/bin/activate'}")
    sys.exit(0)

# Function to scan for devices on the network
def scan_network(ip_range):
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for element in answered:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "hostname": get_hostname(element[1].psrc),
            "vendor": get_mac_vendor(element[1].hwsrc),
            "open_ports": scan_ports(element[1].psrc),
        }
        devices.append(device)

    return devices

# Function to resolve hostname from IP address
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Function to map MAC address to vendor using an API
def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except requests.RequestException:
        return "Unknown"

# Function to scan ports for a given IP address
def scan_ports(ip):
    open_ports = []
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass

    threads = []
    for port in range(1, 1025):  # Scans ports 1 to 1024
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports

# Main function
def main():
    if not os.path.exists("venv"):
        setup_venv()
    
    ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
    print("Scanning network. This may take a while...\n")
    devices = scan_network(ip_range)

    print("Scan Results:\n")
    for device in devices:
        print(f"IP Address: {device['ip']}")
        print(f"MAC Address: {device['mac']}")
        print(f"Hostname: {device['hostname']}")
        print(f"Vendor: {device['vendor']}")
        print(f"Open Ports: {', '.join(map(str, device['open_ports'])) if device['open_ports'] else 'None'}")
        print("-" * 40)

if __name__ == "__main__":
    main()
