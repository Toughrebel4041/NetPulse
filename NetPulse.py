import socket
import json
import nmap
import logging
import sys
import art
import scapy.all as scapy
from scapy import *
from art import *

tprint("NetPulse", font="rnd-larger")
print("Basic Network Scanner Tool by Toughrebel4041")
print("\n")

#host discovery
def discover_hosts(network):
    arp = scapy.ARP(pdst=network)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    result = scapy.srp(packet, timeout=3, verbose=0)[0]
    
    hosts = []
    for sent in result:
        device_info = {
            'ip': sent[1].psrc,
            'mac': semt[1].hwsrc
        }
        hosts.append(device_info)
        
    return hosts

#open_port detection
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
    	      open_ports.append(port)
        sock.close()
    return open_ports
    
#service detection
def detect_service(ip, port):
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        sock.close()
        return banner
    except:
        return none
        
#os detection
def os_detection(network):
    nm = nmap.PortScanner()
    nm.scan(network, arguments='-O') #flag O for OS Detection
    return nm.csv()
    
#main fun
def netpulse():
    network = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    ports = list(range(20, 1025))

    print("Scanning Network . . .")
    devices = discover_hosts(network)
    print(f"Discovered Hosts: {devices}")
    logging.info(f"Discovered Hosts: {devices}")

    print("Detecting OS . . . ")
    os_info = os_detection(network)
    print("OS Detection Results: ")
    print(os_info)
    logging.info(f"OS Detection Results: {os_info}")

    for device in devices:
        ip = device['ip']
        print(f"\nScanning {ip}")
        open_ports = scan_ports(ip, ports)
        print(f"Open Ports: {open_ports}")
        logging.info(f"Open Ports for {ip}: {open_ports}")

        for port in open_ports:
            service = detect_service(ip, port)
            print(f"Port {port}: {service}")
            logging.info(f"Service on {ip}:{port}: {service}")

            vulnerabilities = detect_vulnerabilities(service)
            print(f"Vulnerabilities on port {port}: {vulnerabilities}")
            logging.info(f"Vulnerabilities on {ip}:{port}: {vulnerabilities}")

            banner = grab_banner(ip, port)
            print(f"Banner on port {port}: {banner}")
            logging.info(f"Banner on {ip}:{port}: {banner}")

    print("Scan complete. Results saved to netpulse.log")
    logging.info("Scan complete.")
  
if __name__ == "__main__":
    netpulse()
