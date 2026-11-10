# ARP — Network Security Toolkit

A Python toolkit for Layer 2/3 network security auditing, built with [Scapy](https://scapy.net/). Includes an ARP-based network scanner for host discovery, an ARP spoofer demonstrating MITM positioning, and a passive HTTP traffic analyzer that flags plaintext credentials — built for hands-on learning of local network attacks and why encryption matters.

## ⚠️ Disclaimer

These tools are built for **educational purposes and authorized security testing only**. Only run them against networks and devices you own, or have explicit written permission to test. Running ARP spoofing or packet sniffing tools against networks you don't control is illegal in most jurisdictions.

## Projects

### 1. `ARPSCANNER.py` — ARP Network Scanner

Broadcasts ARP "who-has" requests across an IP range to discover every live device on a local subnet, mapping each responding host's IP address to its MAC address. Same core technique behind tools like `nmap -sn` and `arp-scan`.

**Usage:**
```bash
sudo python3 ARPSCANNER.py 192.168.1.0/24
```

**Example output:**
```
=============================================
IP ADDRESS           | MAC ADDRESS
=============================================
192.168.1.1           | aa:bb:cc:dd:ee:ff
192.168.1.42          | 11:22:33:44:55:66
=============================================
```

---

### 2. `ARPSPOOFER.py` — ARP Spoofer (MITM Demo)

Demonstrates ARP cache poisoning by sending continuous forged ARP replies to a target device and its gateway, tricking both into routing their traffic through the attacker's machine. Includes automatic ARP table restoration on exit (Ctrl+C) so target devices aren't left in a broken state.

**How it works:** ARP is stateless and unauthenticated — any device accepts an ARP reply even if it never requested one, silently overwriting its cache. This tool exploits that to position itself between a target and its gateway, the same technique used in real-world MITM attacks on public/shared networks.

**Usage:**
```bash
sudo python3 ARPSPOOFER.py <target_ip> <gateway_ip>
```

---

### 3. `HTTPANALYZER.py` — Passive HTTP Traffic Analyzer

Sniffs TCP traffic on port 80, reconstructs raw HTTP requests, and extracts visited URLs and any fields that look like login credentials — demonstrating in real time why plaintext HTTP (as opposed to HTTPS) exposes sensitive data to anyone on the same network.

**Usage:**
```bash
sudo python3 HTTPANALYZER.py
sudo python3 HTTPANALYZER.py eth0        # specific interface (Linux/macOS)
python HTTPANALYZER.py "" 30             # Windows, auto-stop after 30s
```

> **Note:** This only sees unencrypted HTTP (port 80) traffic. Most modern websites use HTTPS, so testing against real-world sites will likely show little to no output — this is expected. To see it work, point a browser at a plain-HTTP local server (`python -m http.server 80`) on another machine on the same network.

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/): `pip install scapy`
- Root/Administrator privileges (raw packet access)
- **Windows users:** also requires [Npcap](https://npcap.com/#download) installed in "WinPcap API-compatible mode"

## Why This Project

Built as part of a self-structured cybersecurity learning roadmap, these tools exist to make core networking concepts — ARP resolution, MITM positioning, and the real-world risk of unencrypted traffic — concrete and visible rather than purely theoretical.
