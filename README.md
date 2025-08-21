# Nmap-Clone
A simple Nmap-like port scanner written in Python. Features include:  TCP Connect Scan – detects open ports quickly  SYN Scan (Stealth) – faster, requires Scapy  Basic OS Detection – guesses the target OS using TTL values  Common service identification (e.g., HTTP, SSH, MySQL, RDP, etc.)  Built for learning cybersecurity &amp; networking concepts 🛡️
# Python Nmap Clone 🕵️‍♂️

A simple Python-based port scanner with:
- TCP Connect Scan
- SYN Scan (requires Scapy)
- Basic OS detection via TTL

## Installation
```bash
git clone https://github.com/yourusername/PortScanner.git
cd PortScanner
pip install scapy

## Usage

```bash
python3 nmap_clone.py -t <target-ip> [-s] [-o]
