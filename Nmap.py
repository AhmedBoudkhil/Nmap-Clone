import socket
from concurrent.futures import ThreadPoolExecutor
import platform
import subprocess
import argparse
import re
from datetime import datetime
import random


try:
    from scapy.all import IP,TCP,sr1
    SCAPY_AVAILABLE = True
except ImportError :
    SCAPY_AVAILABLE = False
    print("[!]Scapy isn't available !")
   

# Dictionary of common ports and protocols for better banners
COMMON_PORTS = {
    
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 623: "IPMI", 993: "IMAPS", 995: "POP3S",
    3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 1433: "MSSQL",
}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Port Scanner + OS detection")
    parser.add_argument('-t',"--target",required=True,help="Target IP to scan")
    parser.add_argument('-s',"--ss",action="store_true",help="SYN Scan (Stealth scanning)")
    parser.add_argument('-o',"--os",action="store_true",help="OS detection")
    return parser.parse_args()


open_ports = []

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((ip, port)) == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"[+] Port {port} ({service}) OPEN")
            open_ports.append(port)
        sock.close()
    except:
        pass

def scan(ip):
    start_port, end_port = 1, 1024
    threads = 100
    print(f"[*] Scanning {ip} from port {start_port} to {end_port}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)


def syn_scan(target, ports):
    if not SCAPY_AVAILABLE:
        print("[!] SYN scan requires Scapy. Install it first.")
        return []

    print(f"[*] Performing SYN scan on {target}...")
    found_ports = []

    for port in ports:
        ip = IP(dst=target)
        tcp = TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )

        resp = sr1(ip/tcp, timeout=1, verbose=0)

        if resp is None:
            continue   # No response (filtered or dropped)

        if resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK (open)
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"[+] Port {port} ({service}) OPEN [SYN]")
                open_ports.append(port)
                found_ports.append(port)

                # Send RST to close the half-open connection
                rst = TCP(sport=tcp.sport, dport=port, flags="R")
                sr1(ip/rst, timeout=1, verbose=0)

            elif resp[TCP].flags == 0x14:  # RST-ACK (closed)
                pass  # closed port

    return found_ports


            

def os_detection_ping(ip):
    # Use the correct ping command based on the operating system
    if platform.system().lower() == "windows":
        command = ['ping', '-n', '1', ip]
    else:
        command = ['ping', '-c', '1', ip]
    
    try:
        # Run the ping command
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print(f"[!] Ping to {ip} failed. Host may be down or blocking ICMP.")
        return

    ttl = None
    output = result.stdout

    # Loop through each line of the output to find the TTL
    for line in output.splitlines():

        # Use regex to find a pattern like 'ttl=123' (case-insensitive)

        match = re.search(r'ttl=(\d+)', line, re.IGNORECASE)

        if match:
           
            ttl = int(match.group(1))
            
            break

    
    if ttl:
        print(f"\n[*] Ping successful for {ip}")
        print(f"[*] Detected TTL: {ttl}")
        if ttl <= 64:
            print("[*] Likely OS: Linux / Unix / macOS 🐧")
        elif ttl <= 128:
            print("[*] Likely OS: Windows ❖")
        elif ttl <= 255:
            print("[*] Likely OS: Cisco / Solaris / HPUX 🌐")
        else:
            print("[*] Unknown OS")
    else:
       
        print(f"[!] Could not extract TTL from the ping response for {ip}.")




if __name__ == "__main__":
    args = parse_arguments()
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    ports_to_scan = [22, 80, 443, 3306, 8080]

    target = args.target
    print(f"[*] Starting scan of {target} at {current_time}")

    # Normal TCP scan
    scan(target)
    if open_ports:
        print(f"\n[*] TCP Connect Scan found open ports: {open_ports}")
    else:
        print("\n[!] No open ports found with TCP connect scan.")


    # SYN scan 
    if args.ss:
        syn_scan(target, ports_to_scan)
    if open_ports:
        print(f"\n[*] SYN Scan found open ports: {open_ports}")
    else:
        print("\n[!] No open ports found with SYN scan.")



    # OS detection 
    if args.os:
        if open_ports:
            print(f"\n[*] Attempting OS detection using ping...")
            os_detection_ping(target)
        else:
            print("[!] No open ports found, skipping OS detection.")
