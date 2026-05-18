import socket
import re
import math
import subprocess
import platform
import random
import requests
import json
from datetime import datetime

# Try to import scapy for packet sniffing
try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try to import dns for DNS lookup
try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ============================================
# PART 1: NETWORK SCANNER & PORT ANALYZER
# ============================================

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt"
}

VULN_DB = {
    "OpenSSH_7.4": {"cves": ["CVE-2017-15906"], "risk": "HIGH", "fix": "Upgrade to OpenSSH 7.9+"},
    "Apache_2.4.41": {"cves": ["CVE-2020-9490"], "risk": "MEDIUM", "fix": "Upgrade to Apache 2.4.46+"}
}

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123", "admin"
}

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port, COMMON_PORTS.get(port, "Unknown")
    except:
        pass
    return None

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 22:
            sock.send(b"SSH-2.0-Client\r\n")
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner[:150]
    except:
        return "Banner not available"

def extract_version_from_banner(banner, service):
    if service == "SSH":
        match = re.search(r'SSH-([\d\.]+)', banner)
        if match:
            return f"OpenSSH_{match.group(1)}"
    elif service == "HTTP":
        if "Apache" in banner:
            match = re.search(r'Apache/([\d\.]+)', banner)
            if match:
                return f"Apache_{match.group(1)}"
    return None

def check_vulnerabilities(version_key):
    if version_key and version_key in VULN_DB:
        return VULN_DB[version_key]
    return None

def scan_host(ip, ports):
    open_ports = []
    print(f"📡 Scanning {ip}...")
    for port in ports:
        result = scan_port(ip, port)
        if result:
            port, service = result
            banner = grab_banner(ip, port)
            version_info = extract_version_from_banner(banner, service)
            vulns = check_vulnerabilities(version_info)
            open_ports.append((port, service, banner, vulns))
    return open_ports

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def network_scanner():
    print("\n" + "=" * 70)
    print("🔍 NETWORK SCANNER & PORT ANALYZER")
    print("=" * 70)
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY\n")
    
    my_ip = get_my_ip()
    print(f"💻 Your IP address: {my_ip}")
    network_prefix = '.'.join(my_ip.split('.')[:3])
    
    start_ip = input(f"Start IP (default: {network_prefix}.1): ") or f"{network_prefix}.1"
    end_ip = input(f"End IP (default: {network_prefix}.254): ") or f"{network_prefix}.254"
    
    try:
        start_octet = int(start_ip.split('.')[-1])
        end_octet = int(end_ip.split('.')[-1])
    except:
        start_octet, end_octet = 1, 254
    
    ports_to_scan = COMMON_PORTS
    print(f"\n🔎 Scanning {network_prefix}.{start_octet}-{end_octet}")
    print(f"⏰ Started at: {datetime.now()}\n")
    
    results = {}
    for last_octet in range(start_octet, end_octet + 1):
        ip = f"{network_prefix}.{last_octet}"
        open_ports = scan_host(ip, ports_to_scan.keys())
        if open_ports:
            results[ip] = open_ports
    
    print("\n📊 SCAN RESULTS")
    print("=" * 70)
    if results:
        for ip, ports in results.items():
            print(f"\n🎯 Host: {ip}")
            for port, service, banner, vulns in ports:
                print(f"     🔓 Port {port}/tcp → {service}")
                if vulns:
                    print(f"        ⚠️ VULNERABLE: {vulns['cves']} - {vulns['fix']}")
    else:
        print("❌ No live hosts found.")
    print("=" * 70)
    input("\nPress Enter to continue...")

# ============================================
# PART 2: PASSWORD STRENGTH ANALYZER
# ============================================

def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(c in "!@#$%^&*" for c in password): charset_size += 32
    if charset_size == 0: return 0
    return len(password) * math.log2(charset_size)

def estimate_cracking_time(entropy):
    guesses_per_second = 1_000_000_000
    if entropy <= 0: return "Instant"
    seconds = (2 ** entropy) / guesses_per_second
    if seconds < 60: return f"{seconds:.1f} seconds"
    if seconds < 3600: return f"{seconds/60:.1f} minutes"
    if seconds < 86400: return f"{seconds/3600:.1f} hours"
    if seconds < 31536000: return f"{seconds/86400:.1f} days"
    return f"{seconds/31536000:.1f} years"

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: feedback.append("✗ Too short")
    
    if re.search(r'[a-z]', password): score += 1
    else: feedback.append("✗ Add lowercase")
    if re.search(r'[A-Z]', password): score += 1
    else: feedback.append("✗ Add uppercase")
    if re.search(r'\d', password): score += 1
    else: feedback.append("✗ Add numbers")
    if re.search(r'[!@#$%^&*]', password): score += 2
    else: feedback.append("⚠️ Add special chars")
    
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback = ["✗ Common password!"]
    
    entropy = calculate_entropy(password)
    if score >= 6: strength, emoji = "VERY STRONG", "🟢"
    elif score >= 4: strength, emoji = "STRONG", "🔵"
    elif score >= 2: strength, emoji = "WEAK", "🟡"
    else: strength, emoji = "VERY WEAK", "🔴"
    
    return {"strength": strength, "emoji": emoji, "score": score, 
            "feedback": feedback, "crack_time": estimate_cracking_time(entropy)}

def generate_strong_password():
    words = ["Blue", "Tiger", "Coffee", "Storm", "Forest", "Mountain"]
    return f"{random.choice(words)}{random.randint(10,999)}!{random.choice(words)}"

def password_analyzer():
    print("\n" + "=" * 60)
    print("🔐 PASSWORD STRENGTH ANALYZER")
    print("=" * 60)
    while True:
        print("\n1. Check password\n2. Generate strong password\n3. Back")
        choice = input("Choose: ")
        if choice == "1":
            pwd = input("Enter password: ")
            res = check_password_strength(pwd)
            print(f"\n{res['emoji']} Strength: {res['strength']} ({res['score']}/7)")
            print(f"⏱️ Cracking time: {res['crack_time']}")
            print("Feedback:", ", ".join(res['feedback']))
            input("\nPress Enter...")
        elif choice == "2":
            print(f"\n🔑 Generated: {generate_strong_password()}")
            input("\nPress Enter...")
        elif choice == "3":
            break

# ============================================
# PART 3: PACKET SNIFFER (IMPROVED FOR ICMP/WINDOWS)
# ============================================

packet_count = 0
packet_limit = 0
show_details = False

def check_admin_windows():
    """Check if running as Administrator on Windows"""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return True

def process_packet(packet):
    """Process and display packet information"""
    global packet_count
    if packet_limit > 0 and packet_count >= packet_limit:
        return
    packet_count += 1
    print(f"\n📦 PACKET #{packet_count}")
    print("-" * 50)
    
    # Ethernet Layer
    if packet.haslayer("Ether"):
        eth = packet["Ether"]
        print(f"🔌 MAC: {eth.src} → {eth.dst}")
    
    # IP Layer
    if packet.haslayer("IP"):
        ip = packet["IP"]
        print(f"🌐 IP:   {ip.src} → {ip.dst}")
        print(f"📡 Proto: {ip.proto}")
    
    # ICMP Layer (Ping)
    if packet.haslayer("ICMP"):
        icmp = packet["ICMP"]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable"}
        icmp_type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
        print(f"⚡ ICMP: {icmp_type_name} (Type: {icmp.type}, Code: {icmp.code})")
        
        if icmp.type == 8:
            print("   → This is a PING REQUEST")
        elif icmp.type == 0:
            print("   → This is a PING REPLY")
    
    # TCP Layer
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        print(f"🔗 TCP:  Port {tcp.sport} → {tcp.dport}")
        print(f"🏁 Flags: {tcp.flags}")
    
    # UDP Layer
    if packet.haslayer("UDP"):
        udp = packet["UDP"]
        print(f"📡 UDP:  Port {udp.sport} → {udp.dport}")
    
    # ARP Layer (Always works on Windows)
    if packet.haslayer("ARP"):
        arp = packet["ARP"]
        print(f"🖧 ARP:  {arp.psrc} → {arp.pdst}")
    
    # Payload
    if show_details and packet.haslayer("Raw"):
        raw = packet["Raw"]
        try:
            data = raw.load.decode('utf-8', errors='ignore')[:100]
            if data:
                print(f"📄 Data: {data[:80]}...")
        except:
            print(f"📄 Data: [{len(raw.load)} bytes]")
    
    print("-" * 50)
    
    if packet_limit > 0 and packet_count >= packet_limit:
        print(f"\n✅ Reached packet limit ({packet_limit})")

def packet_sniffer_alternative():
    """Alternative packet sniffer using socket (no Scapy needed)"""
    print("\n" + "=" * 60)
    print("📡 RAW SOCKET PACKET SNIFFER (Alternative)")
    print("=" * 60)
    print("⚠️ This method captures packets at socket level\n")
    
    try:
        import socket as sock_lib
        
        raw_socket = sock_lib.socket(sock_lib.AF_INET, sock_lib.SOCK_RAW, sock_lib.IPPROTO_IP)
        raw_socket.setsockopt(sock_lib.IPPROTO_IP, sock_lib.IP_HDRINCL, 1)
        raw_socket.bind((get_my_ip(), 0))
        raw_socket.ioctl(sock_lib.SIO_RCVALL, sock_lib.RCVALL_ON)
        
        packet_limit_local = int(input("\nPackets to capture (e.g., 5): ") or 5)
        show_data = input("Show packet data? (y/n): ").lower() == 'y'
        
        print("\n🔍 Capturing packets... Press Ctrl+C to stop\n")
        
        count = 0
        while count < packet_limit_local:
            try:
                packet, addr = raw_socket.recvfrom(65535)
                count += 1
                
                print(f"\n📦 PACKET #{count}")
                print(f"   From: {addr[0]}")
                print(f"   Size: {len(packet)} bytes")
                
                if show_data and len(packet) > 20:
                    hex_data = ' '.join(f'{b:02x}' for b in packet[:50])
                    print(f"   Data: {hex_data}...")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                break
        
        raw_socket.ioctl(sock_lib.SIO_RCVALL, sock_lib.RCVALL_OFF)
        raw_socket.close()
        
        print(f"\n✅ Captured {count} packets")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("   Raw sockets require Administrator privileges on Windows")
    
    input("\nPress Enter to continue...")

def packet_sniffer():
    """Main packet sniffer with ICMP support and Windows fixes"""
    global packet_count, packet_limit, show_details
    
    print("\n" + "=" * 70)
    print("📡 PACKET SNIFFER / NETWORK TRAFFIC ANALYZER")
    print("=" * 70)
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("📌 Captures and analyzes network packets\n")
    
    # Check Admin privileges on Windows
    if platform.system() == "Windows" and not check_admin_windows():
        print("❌ Administrator privileges required for packet capture on Windows!")
        print("\n🔧 FIX: Close this window and reopen as Administrator:")
        print("   1. Right-click on Command Prompt or PowerShell")
        print("   2. Select 'Run as Administrator'")
        print("   3. Run the toolkit again\n")
        input("Press Enter to continue...")
        return
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not installed!")
        print("\n📌 OPTIONS:")
        print("1. Install Scapy + Npcap (Recommended)")
        print("2. Use Alternative Raw Socket Sniffer")
        print("3. Back to Main Menu")
        
        choice = input("\nChoose (1-3): ")
        
        if choice == "1":
            print("\n🔧 INSTALLATION INSTRUCTIONS:")
            print("═" * 50)
            print("\nStep 1: Install Npcap")
            print("   • Download from: https://npcap.com/")
            print("   • Run installer as Administrator")
            print("   • Check 'Install in WinPcap API-compatible Mode'")
            print("\nStep 2: Install Scapy")
            print("   • Run: pip install scapy")
            print("\nStep 3: Restart your computer")
            print("\nAfter installation, run this tool again!")
            input("\nPress Enter to continue...")
        elif choice == "2":
            packet_sniffer_alternative()
        return
    
    try:
        # Tell user about ICMP limitation
        print("💡 TIPS FOR CAPTURING PACKETS:")
        print("   • Run as Administrator for full capture")
        print("   • ICMP (ping) works with Admin privileges")
        print("   • Try 'tcp' or 'port 80' if ICMP doesn't work")
        print("   • Generate traffic by pinging a website\n")
        
        # Get and show interfaces
        print("📡 Available Network Interfaces:")
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            for i, iface in enumerate(interfaces[:5]):
                print(f"   {i+1}. {iface}")
        except:
            print("   (Could not list interfaces)")
        
        print("\n⚙️ CONFIGURATION:")
        packet_limit = int(input("Packets to capture (e.g., 10): ") or 10)
        show_details = input("Show packet payload? (y/n): ").lower() == 'y'
        
        print("\n📌 FILTER EXAMPLES:")
        print("   • 'icmp'     - Ping packets (requires Admin)")
        print("   • 'tcp'      - All TCP traffic")
        print("   • 'udp'      - All UDP traffic")
        print("   • 'port 80'  - HTTP web traffic")
        print("   • 'port 443' - HTTPS traffic")
        print("   • 'arp'      - ARP requests (always works)")
        print("   • (Enter)    - No filter")
        
        filter_input = input("\nApply filter: ").strip()
        if not filter_input:
            filter_input = None
        
        # Special warning for ICMP
        if filter_input == "icmp" and platform.system() == "Windows":
            print("\n⚠️ ICMP capture requires Administrator privileges!")
            print("   If no packets appear, try:")
            print("   1. Run as Administrator")
            print("   2. Try 'arp' or 'tcp' filter instead")
            print("   3. Generate traffic: ping 8.8.8.8 in another terminal\n")
        
        packet_count = 0
        
        print("\n" + "=" * 70)
        print("🔍 STARTING PACKET CAPTURE...")
        print("Press Ctrl+C to stop")
        print("=" * 70 + "\n")
        
        # Generate some test traffic if needed
        if filter_input == "icmp":
            print("💡 To generate ICMP traffic, open another terminal and run:")
            print("   ping 8.8.8.8 -t\n")
        
        try:
            timeout = 60 if filter_input == "icmp" else 30
            
            if filter_input:
                sniff(prn=process_packet, store=False, filter=filter_input, 
                      count=packet_limit, timeout=timeout)
            else:
                sniff(prn=process_packet, store=False, count=packet_limit, timeout=timeout)
            
            if packet_count == 0:
                print("\n⚠️ No packets captured!")
                print("\n🔧 TROUBLESHOOTING:")
                print("   1. Run as Administrator")
                print("   2. Try 'arp' filter instead")
                print("   3. Open another terminal and run: ping 8.8.8.8")
                print("   4. Make sure Npcap is installed correctly")
            else:
                print(f"\n✅ Capture complete! Total packets: {packet_count}")
            
        except PermissionError:
            print("\n❌ Permission denied! Run as Administrator!")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("\n🔧 TROUBLESHOOTING STEPS:")
            print("   1. Run as Administrator (Right-click → Run as Administrator)")
            print("   2. Install Npcap from https://npcap.com/")
            print("   3. Try filter 'arp' (always works)")
            print("   4. Restart your computer")
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️ Capture stopped. Captured {packet_count} packets")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("   Try running as Administrator")
    
    input("\nPress Enter to continue...")

# ============================================
# PART 4: GEOIP TRACKER
# ============================================

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except:
        return None

def get_ip_location(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'country': data.get('country', 'N/A'),
                'city': data.get('city', 'N/A'),
                'region': data.get('regionName', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'lat': data.get('lat', 'N/A'),
                'lon': data.get('lon', 'N/A'),
                'timezone': data.get('timezone', 'N/A'),
                'zip': data.get('zip', 'N/A')
            }
        return None
    except:
        return None

def geoip_tracker():
    print("\n" + "=" * 70)
    print("🌍 GEOIP TRACKER - IP Location Finder")
    print("=" * 70)
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("📌 Shows geographical location of IP addresses\n")
    
    while True:
        print("\n📋 OPTIONS:")
        print("1. 🌐 Track My Own IP")
        print("2. 🎯 Track Specific IP Address")
        print("3. 🔍 Track Domain Name")
        print("4. 📊 Track Multiple IPs (Batch)")
        print("5. 🔙 Back to Main Menu")
        
        choice = input("\nChoose (1-5): ")
        
        if choice == "1":
            print("\n🔍 Fetching your public IP...")
            ip = get_public_ip()
            if ip:
                print(f"📡 Your Public IP: {ip}")
                print("\n📍 FETCHING LOCATION DATA...\n")
                location = get_ip_location(ip)
                if location:
                    print("═" * 50)
                    print("📍 LOCATION INFORMATION")
                    print("═" * 50)
                    print(f"🌍 Country:    {location['country']}")
                    print(f"🏙️  City:       {location['city']}")
                    print(f"📍 Region:     {location['region']}")
                    print(f"📮 Zip Code:   {location['zip']}")
                    print(f"🏢 ISP:        {location['isp']}")
                    print(f"🕐 Timezone:   {location['timezone']}")
                    print(f"🗺️  Coordinates: {location['lat']}, {location['lon']}")
                    print("═" * 50)
                else:
                    print("❌ Could not get location data")
            else:
                print("❌ Could not get public IP")
            input("\nPress Enter to continue...")
        
        elif choice == "2":
            ip = input("\nEnter IP address: ").strip()
            location = get_ip_location(ip)
            if location:
                print("\n" + "═" * 50)
                print(f"📍 IP: {ip}")
                print("═" * 50)
                print(f"🌍 Country:    {location['country']}")
                print(f"🏙️  City:       {location['city']}")
                print(f"📍 Region:     {location['region']}")
                print(f"🏢 ISP:        {location['isp']}")
                print(f"🕐 Timezone:   {location['timezone']}")
                print(f"🗺️  Coordinates: {location['lat']}, {location['lon']}")
                print("═" * 50)
            else:
                print(f"❌ Could not get location for {ip}")
            input("\nPress Enter to continue...")
        
        elif choice == "3":
            domain = input("\nEnter domain name (e.g., google.com): ").strip()
            try:
                ip = socket.gethostbyname(domain)
                print(f"\n🔍 {domain} → {ip}")
                location = get_ip_location(ip)
                if location:
                    print("\n" + "═" * 50)
                    print(f"📍 SERVER LOCATION FOR {domain}")
                    print("═" * 50)
                    print(f"🌍 Country:    {location['country']}")
                    print(f"🏙️  City:       {location['city']}")
                    print(f"📍 Region:     {location['region']}")
                    print(f"🏢 ISP:        {location['isp']}")
                    print("═" * 50)
                else:
                    print("❌ Could not get location")
            except:
                print(f"❌ Could not resolve {domain}")
            input("\nPress Enter to continue...")
        
        elif choice == "4":
            print("\n📝 Enter IPs one per line (type 'done' to finish):")
            ips = []
            while True:
                ip_input = input("> ").strip()
                if ip_input.lower() == 'done':
                    break
                if ip_input:
                    ips.append(ip_input)
            
            if ips:
                print("\n" + "═" * 70)
                print("📊 BATCH LOCATION RESULTS")
                print("═" * 70)
                for ip in ips:
                    location = get_ip_location(ip)
                    if location:
                        print(f"\n📍 {ip} → {location['city']}, {location['country']} ({location['isp']})")
                    else:
                        print(f"\n📍 {ip} → Location not found")
                print("═" * 70)
            input("\nPress Enter to continue...")
        
        elif choice == "5":
            break
        
        else:
            print("❌ Invalid choice")

# ============================================
# PART 5: DNS LOOKUP TOOL
# ============================================

def dns_forward_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def dns_reverse_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None

def dns_enumeration(domain):
    if not DNS_AVAILABLE:
        return None
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
    results = {}
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(answer) for answer in answers]
        except:
            results[record] = []
    
    return results

def dns_lookup_menu():
    print("\n" + "=" * 70)
    print("🌐 DNS LOOKUP & ENUMERATION TOOL")
    print("=" * 70)
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("📌 Essential tool for network reconnaissance\n")
    
    if not DNS_AVAILABLE:
        print("⚠️ Note: Full DNS enumeration requires dnspython")
        print("   Install with: pip install dnspython\n")
    
    while True:
        print("\n📋 OPTIONS:")
        print("1. 🔍 Forward DNS Lookup (Domain → IP)")
        print("2. 🔄 Reverse DNS Lookup (IP → Domain)")
        print("3. 📋 Full DNS Enumeration (All Records)")
        print("4. 📊 Batch DNS Lookup")
        print("5. 🔙 Back to Main Menu")
        
        choice = input("\nChoose (1-5): ")
        
        if choice == "1":
            domain = input("\nEnter domain name (e.g., google.com): ").strip()
            ip = dns_forward_lookup(domain)
            if ip:
                print(f"\n✅ {domain} → {ip}")
            else:
                print(f"\n❌ Could not resolve {domain}")
            input("\nPress Enter to continue...")
        
        elif choice == "2":
            ip = input("\nEnter IP address (e.g., 8.8.8.8): ").strip()
            hostname = dns_reverse_lookup(ip)
            if hostname:
                print(f"\n✅ {ip} → {hostname}")
            else:
                print(f"\n❌ No PTR record found for {ip}")
            input("\nPress Enter to continue...")
        
        elif choice == "3":
            if not DNS_AVAILABLE:
                print("\n❌ dnspython not installed!")
                print("   Install with: pip install dnspython")
                input("\nPress Enter...")
                continue
            
            domain = input("\nEnter domain name: ").strip()
            print(f"\n🔍 Enumerating DNS records for {domain}...\n")
            results = dns_enumeration(domain)
            
            if results:
                print("═" * 50)
                print(f"📋 DNS RECORDS FOR {domain}")
                print("═" * 50)
                for record, values in results.items():
                    if values:
                        print(f"\n📌 {record} Records:")
                        for value in values[:5]:
                            print(f"   • {value}")
                        if len(values) > 5:
                            print(f"   ... and {len(values) - 5} more")
            else:
                print("❌ Could not retrieve DNS records")
            input("\nPress Enter to continue...")
        
        elif choice == "4":
            print("\n📝 Enter domains one per line (type 'done' to finish):")
            domains = []
            while True:
                domain_input = input("> ").strip()
                if domain_input.lower() == 'done':
                    break
                if domain_input:
                    domains.append(domain_input)
            
            if domains:
                print("\n" + "═" * 70)
                print("📊 BATCH DNS LOOKUP RESULTS")
                print("═" * 70)
                for domain in domains:
                    ip = dns_forward_lookup(domain)
                    if ip:
                        print(f"\n✅ {domain:30} → {ip}")
                    else:
                        print(f"\n❌ {domain:30} → [Not Resolved]")
                print("═" * 70)
            input("\nPress Enter to continue...")
        
        elif choice == "5":
            break
        
        else:
            print("❌ Invalid choice")

# ============================================
# PART 6: MAC ADDRESS SPOOFER
# ============================================

def get_network_adapters_windows():
    try:
        cmd = ['powershell', '-Command', 
               'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -ExpandProperty Name']
        result = subprocess.run(cmd, capture_output=True, text=True)
        adapters = [adapter.strip() for adapter in result.stdout.strip().split('\n') if adapter.strip()]
        return adapters
    except:
        return []

def get_current_mac_windows(adapter_name):
    try:
        cmd = ['powershell', '-Command', 
               f'Get-NetAdapter -Name "{adapter_name}" | Select-Object -ExpandProperty MacAddress']
        result = subprocess.run(cmd, capture_output=True, text=True)
        mac = result.stdout.strip()
        if mac and mac != '':
            return mac
    except:
        pass
    
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if adapter_name.lower() in line.lower():
                for j in range(i, min(i+10, len(lines))):
                    if 'Physical Address' in lines[j]:
                        mac_match = re.search(r'Physical Address[.\s]+: ([\da-fA-F-]{17})', lines[j])
                        if mac_match:
                            return mac_match.group(1).replace('-', ':')
    except:
        pass
    return None

def generate_random_mac():
    first_byte = random.randint(0x00, 0xFE)
    first_byte = first_byte if first_byte % 2 == 0 else first_byte + 1
    mac = [first_byte] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ':'.join(f'{b:02x}' for b in mac)

def generate_vendor_mac():
    vendor_prefixes = [
        '00:1A:2B', '00:50:56', '08:00:27', '00:0C:29', '00:15:5D',
        'C8:FF:28', 'AC:BC:32', '00:1E:C2', 'B8:27:EB', '00:14:22'
    ]
    prefix = random.choice(vendor_prefixes)
    suffix = f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
    return f"{prefix}:{suffix}"

def change_mac_windows_manual():
    print("\n📌 MANUAL MAC ADDRESS CHANGE FOR WINDOWS:")
    print("═" * 60)
    print("\nMETHOD 1: Device Manager (Easiest)")
    print("   1. Press Win + X → Device Manager")
    print("   2. Expand 'Network adapters'")
    print("   3. Right-click your adapter → Properties")
    print("   4. Go to 'Advanced' tab")
    print("   5. Find 'Network Address' or 'Locally Administered Address'")
    print("   6. Enter new MAC address (without colons, e.g., 02AB12CD34EF)")
    print("   7. Click OK and restart the adapter\n")
    
    print("METHOD 2: PowerShell (Run as Administrator)")
    print("   • Check adapters: Get-NetAdapter | Select Name, MacAddress")
    print("   • Change MAC: Set-NetAdapter -Name 'YOUR_ADAPTER' -MacAddress '02AB12CD34EF'")
    print("   • Restart adapter: Restart-NetAdapter -Name 'YOUR_ADAPTER'\n")
    
    print("METHOD 3: Technitium MAC Address Changer (Free Tool)")
    print("   • Download: https://technitium.com/tmac/")

def mac_spoofer_windows():
    print("\n" + "=" * 70)
    print("🖧 MAC ADDRESS SPOOFER / CHANGER")
    print("=" * 70)
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("📌 Demonstrates network anonymity techniques\n")
    
    adapters = get_network_adapters_windows()
    
    if adapters:
        print("📡 AVAILABLE NETWORK ADAPTERS:")
        for i, adapter in enumerate(adapters, 1):
            mac = get_current_mac_windows(adapter)
            mac_display = f" ({mac})" if mac else ""
            print(f"   {i}. {adapter}{mac_display}")
        
        print("\n📋 OPTIONS:")
        print("1. 🎲 Generate Random MAC Address")
        print("2. 📖 Show Manual Instructions to Change MAC")
        print("3. 🔙 Back to Main Menu")
        
        choice = input("\nChoose (1-3): ")
        
        if choice == "1":
            print("\n🎲 RANDOM MAC ADDRESSES:")
            for i in range(5):
                print(f"   {i+1}. {generate_random_mac()}")
            print(f"\n   🏭 Vendor MAC: {generate_vendor_mac()}")
            
            print("\n💡 To use these:")
            print("   • Copy the MAC address (without colons, e.g., 02AB12CD34EF)")
            print("   • Follow manual instructions above to apply it")
        
        elif choice == "2":
            change_mac_windows_manual()
        
        elif choice == "3":
            return
    
    else:
        print("⚠️ Could not detect network adapters via PowerShell")
        change_mac_windows_manual()
    
    print("\n" + "=" * 70)
    print("📌 QUICK TIPS:")
    print("   • MAC changes reset after reboot")
    print("   • Some adapters don't support MAC changing")
    print("   • Use Technitium MAC Changer for easy GUI")
    print("=" * 70)
    
    input("\nPress Enter to continue...")

def mac_spoofer_linux():
    print("\n" + "=" * 70)
    print("🖧 MAC ADDRESS SPOOFER / CHANGER FOR LINUX")
    print("=" * 70)
    print("⚠️  Requires sudo privileges\n")
    
    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
    interfaces = re.findall(r'\d+: (eth\d+|wlan\d+|enp\w+|wlp\w+):', result.stdout)
    
    if not interfaces:
        print("❌ No network interfaces found")
        input("\nPress Enter...")
        return
    
    print("📡 Available Interfaces:")
    for iface in interfaces:
        print(f"   • {iface}")
    
    interface = input("\nEnter interface name: ").strip()
    
    result = subprocess.run(['cat', f'/sys/class/net/{interface}/address'], capture_output=True, text=True)
    current_mac = result.stdout.strip()
    
    if current_mac:
        print(f"\n📡 Current MAC: {current_mac}")
    
    print("\n🎲 MAC Options:")
    print("1. Generate Random MAC")
    print("2. Enter Custom MAC")
    
    choice = input("\nChoose (1-2): ")
    
    if choice == "1":
        new_mac = generate_random_mac()
        print(f"\n🎲 Generated MAC: {new_mac}")
    else:
        new_mac = input("Enter new MAC (xx:xx:xx:xx:xx:xx): ").strip()
    
    confirm = input(f"\n⚠️ Change MAC from {current_mac} to {new_mac}? (y/n): ")
    
    if confirm.lower() == 'y':
        print("\n🔄 Changing MAC...")
        commands = [
            f'sudo ifconfig {interface} down',
            f'sudo ifconfig {interface} hw ether {new_mac}',
            f'sudo ifconfig {interface} up'
        ]
        
        for cmd in commands:
            subprocess.run(cmd.split(), capture_output=True)
        
        result = subprocess.run(['cat', f'/sys/class/net/{interface}/address'], capture_output=True, text=True)
        new_current = result.stdout.strip()
        
        if new_current.lower() == new_mac.lower():
            print(f"\n✅ MAC changed successfully!")
            print(f"📡 New MAC: {new_current}")
        else:
            print("\n❌ Failed to change MAC. Try running with sudo.")
    
    input("\nPress Enter...")

def mac_spoofer():
    system = platform.system()
    
    if system == "Windows":
        mac_spoofer_windows()
    elif system == "Linux":
        mac_spoofer_linux()
    else:
        print(f"\n⚠️ {system} MAC changing not fully supported")
        change_mac_windows_manual()
        input("\nPress Enter...")

# ============================================
# PART 7: MAIN MENU
# ============================================

def main():
    while True:
        print("\n" + "=" * 70)
        print("🛡️  CYBERSECURITY NETWORK TOOLKIT")
        print("=" * 70)
        print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
        print("=" * 70)
        print("\n📋 MAIN MENU:")
        print("┌─────────────────────────────────────────────────────────┐")
        print("│  1. 🔍 Network Scanner & Port Analyzer                  │")
        print("│  2. 🔐 Password Strength Analyzer                       │")
        print("│  3. 📡 Packet Sniffer (ICMP/Windows Fixed)              │")
        print("│  4. 🌍 GeoIP Tracker                                    │")
        print("│  5. 🌐 DNS Lookup & Enumeration                         │")
        print("│  6. 🖧 MAC Address Spoofer                               │")
        print("│  7. 🚪 Exit                                             │")
        print("└─────────────────────────────────────────────────────────┘")
        
        choice = input("\nSelect tool (1-7): ")
        
        if choice == '1':
            network_scanner()
        elif choice == '2':
            password_analyzer()
        elif choice == '3':
            packet_sniffer()
        elif choice == '4':
            geoip_tracker()
        elif choice == '5':
            dns_lookup_menu()
        elif choice == '6':
            mac_spoofer()
        elif choice == '7':
            print("\n" + "=" * 70)
            print("👋 Thank you for using the Cybersecurity Toolkit!")
            print("🛡️ Stay secure and hack ethically!")
            print("=" * 70)
            break
        else:
            print("❌ Invalid choice! Please enter 1-7")

# ============================================
# RUN THE APPLICATION
# ============================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Application interrupted by user")
        print("Exiting gracefully...")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")