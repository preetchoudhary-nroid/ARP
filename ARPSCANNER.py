#ON A LOCAL Ethernet/wifi subnet, devices resolve IP -> MAC addresses using arp(address Resolution protocol). This script broadcasts an ARP "who-has" request to every address in a given IP range, and all the live devices on the subnet replies with its real MAC address. This is the same technique tools like "nmap -sn" and "arp-scan" use under the hood - its fast because it works at layer 2 and doesnt wait for a full IP level handshake

#USAGE:
#sudo python3 ARP SCANNER.py 192.168.1.0/24
#sudo python3 ARP SCANNER.py #default to 192.168.1.0/24

#NOTE:
#Needs root (raw socket access) and only works on an IP range that is the devic local subnet - ARP does not route across networks.

import sys

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    sys.exit(
        "Scapy is not installed. - pip install scapy --break-system-packages"   
    )

def scan_network(ip_range: str) -> list[dict]:
    print(f"SCANNING NETWORK RANGE: {ip_range}")
#broadcast ethernet frame to every device on the segment
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#ARP request asking "who has this IP?"    
    arp = ARP(pdst=ip_range)
# stack the layers togther ether + arp
    packet = ether / arp
#srp = send and receive packets at layer 2

#timeout=2 gives devices 2 seconds to reply before giving up

    result, _ = srp(packet, timeout=2, verbose=False)

    devices = []
    for _sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def print_results(devices: list[dict]) -> None:
    print(f"{'IP ADDRESS':<20} | {'MAC ADDRESS':<20}")
    for dev in devices:
        print(f"{dev['ip']:<20} | {dev['mac']:<20}")
    print(f"[$] {len(devices)} devices(s) found. \n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    found = scan_network(target)
    print_results(found)