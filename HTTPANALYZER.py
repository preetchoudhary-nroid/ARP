#Passive http traffic sniffer

#plain HTTP (port=80, unlike HTTPS on 443) sends everything - URLs, form data, login fields - as unencrypted plaintext. This script sniffs TCP traffic on port 80, reconstructs the raw HTTP request text, and pulls out the visited URL and any fields that look like login credentials.

#USAGE: 
# sudo python3 HTTPANALYZER.py
# sudo python3 HTTPANALYZER.py eth0

#USAGE:
#   python HTTPANALYZER.py                 # all interfaces, runs until Ctrl+C
#    python HTTPANALYZER.py "Wi-Fi"         # specific interface name (Windows uses names, not eth0)
#    python HTTPANALYZER.py "" 30           # run for 30 seconds then auto-stop

 
import re
import sys
 
try:
    from scapy.all import Raw, sniff
    from scapy.layers.inet import TCP
except ImportError:
    sys.exit("Scapy is not installed. Run: pip install scapy")
 
URL_RE = re.compile(r"(GET|POST)\s+(.*?)\s+HTTP")
HOST_RE = re.compile(r"Host:\s+(.*?)\r\n")
 
# Set to True by the stop_filter once we want sniff() to exit
_stop_requested = False
 
 
def process_packet(packet) -> None:
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
 
    if packet[TCP].dport != 80 and packet[TCP].sport != 80:
        return
 
    payload = packet[Raw].load.decode("utf-8", errors="ignore")
 
    if "GET" in payload or "POST" in payload:
        url_match = URL_RE.search(payload)
        host_match = HOST_RE.search(payload)
        if url_match and host_match:
            full_url = f"http://{host_match.group(1)}{url_match.group(2)}"
            print(f"VISITED - {full_url}")
 
    if "username" in payload.lower() or "password" in payload.lower():
        print(f"DANGER - Unencrypted credential-like data detected:\n{payload}\n")
 
 
def should_stop(_packet) -> bool:
    # sniff() checks this after every packet — lets Ctrl+C actually take effect
    # on Windows instead of blocking forever inside the capture loop.
    return _stop_requested
 
 
if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else None
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else None
 
    print(f"STARTING HTTP TRAFFIC ANALYZER{f' on {iface}' if iface else ''}...")
    print("Press Ctrl+C to stop." if not timeout else f"Will auto-stop after {timeout}s.")
    print("NOTE: needs Npcap installed + terminal running as Administrator.\n")
 
    try:
        sniff(
            filter="tcp port 80",
            prn=process_packet,
            store=0,
            iface=iface,
            timeout=timeout,       # auto-exits after N seconds if set
            stop_filter=should_stop,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit(
            "\n[!] Permission denied opening the network adapter.\n"
            "    -> Make sure Npcap is installed AND you're running this terminal as Administrator."
        )
    except OSError as e:
        sys.exit(
            f"\n[!] OS error opening interface: {e}\n"
            "    -> Usually means Npcap isn't installed, or the interface name is wrong.\n"
            "    -> Run: python -c \"from scapy.all import get_if_list; print(get_if_list())\" to list valid interface names."
        )
 
    print("\nStopped.")