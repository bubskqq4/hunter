#!/usr/bin/env python3

import os
import sys
import time
import socket
import subprocess
import requests
import platform
import json
import re
import threading
import queue
import datetime
import hashlib
import getpass
import ssl
import urllib.parse
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import dns.resolver
import psutil
import netifaces
import ipaddress
import uuid
import random

init()

# -------------------- SETUP --------------------
CONFIG_DIR = "config"
CONFIG_FILES = {
    "ports.json": {"common_ports": [21, 22, 23, 25, 53, 80, 443, 8080], "extended_ports": list(range(1, 1001))},
    "settings.json": {"timeout": 0.5, "max_threads": 50, "log_file": "hutnter.log", "ddos_threshold": 100},
    "whitelist.json": {"allowed_ips": []},
    "users.json": {"users": [{"id": str(uuid.uuid4()), "username": "Ethan", "password": hashlib.sha256("Admin".encode()).hexdigest(), "role": "admin"}]}
}

if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)
    print(Fore.CYAN + "[+] Initialized config grid." + Style.RESET_ALL)
for file_name, file_content in CONFIG_FILES.items():
    file_path = os.path.join(CONFIG_DIR, file_name)
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump(file_content, f, indent=4)
        print(Fore.CYAN + f"[+] Deployed {file_name} to config grid." + Style.RESET_ALL)

# Load configuration
with open(os.path.join(CONFIG_DIR, "ports.json"), "r") as f:
    PORTS_CONFIG = json.load(f)
with open(os.path.join(CONFIG_DIR, "settings.json"), "r") as f:
    SETTINGS = json.load(f)
with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
    USERS = json.load(f)
with open(os.path.join(CONFIG_DIR, "whitelist.json"), "r") as f:
    WHITELIST = json.load(f)

# -------------------- LEGAL NOTICE --------------------
LEGAL = """
================== LEGAL GRID ==================
HUTNTER is for ethical penetration testing only.
Unauthorized access to networks or systems is ILLEGAL.
Comply with all laws. Developer not liable for misuse.
===============================================
"""

# -------------------- CYBERPUNK BANNER --------------------
def banner():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(Fore.MAGENTA + r"""
       ╔═══╗   ╔╗       ╔════╗╔═══╗╔═══╗╔════╗
       ║╔═╗║   ║║       ║╔╗╔╗║╚╗╔╗║╚╗╔╗║╚══╗║
       ║╚══╦══╦╩╠══╦═╦══╩╩╩═╩═╩╩╩═╩╩╩═╩══╩╩══╦══╦══╦══╗
       ╚══╗║╔╗║╔╠══╩╔╩══╦╦╦╗╔╦╦╗╔╦╗╔╦╦╦╗╚══╗║╔═╩╩╩╚╗╔╗║
       ║╚═╝║╚╝║╚╩══╩╚╩══╬╩╩╩╬╩╩╩╬╩╩╬╩╩╩╩╩╩╩╬╩═╗╔╗╚╝╚╝╚═╗
       ╚═══╩══╩══╩══╩══╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩══╝
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "          HUTNTER | NEON GRID DOMINATOR" + Style.RESET_ALL)
    print(Fore.GREEN + LEGAL + Style.RESET_ALL)

# -------------------- LOGGING --------------------
def log_event(message):
    with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# -------------------- USER LOGIN --------------------
def user_login():
    banner()
    print(Fore.MAGENTA + "=== ACCESS THE GRID ===" + Style.RESET_ALL)
    while True:
        username = input(Fore.CYAN + "[NETMASK] Enter username: " + Style.RESET_ALL).strip()
        password = getpass.getpass(Fore.CYAN + "[KEYCODE] Enter password: " + Style.RESET_ALL)
        with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
            users_data = json.load(f)
        for user in users_data['users']:
            if user['username'] == username and user['password'] == hashlib.sha256(password.encode()).hexdigest():
                log_event(f"{user['role'].capitalize()} login successful: {username}")
                return {"id": user['id'], "username": username, "role": user['role']}
        print(Fore.RED + "[-] Invalid NETMASK or KEYCODE. Retry." + Style.RESET_ALL)
        log_event(f"Login failed: {username}")
        print(Fore.CYAN + "[!] Register via option 32 or run dashboard.py for sign-up." + Style.RESET_ALL)
        input(Fore.CYAN + "[>] Press Enter to retry..." + Style.RESET_ALL)
        banner()

# -------------------- NETWORK TOOLS --------------------
def ping_host():
    target = input(Fore.CYAN + "[>] Target host/IP: " + Style.RESET_ALL)
    response = os.system(f"ping -c 4 {target}" if platform.system() != "Windows" else f"ping {target}")
    result = "Host is up." if response == 0 else "Host is down or unreachable."
    print(Fore.GREEN + f"[+] {result}" + Style.RESET_ALL)
    log_event(f"Pinged {target}: {result}")

def port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["common_ports"]
    print(Fore.MAGENTA + f"[~] Scanning {target} on common ports..." + Style.RESET_ALL)
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
            s.close()
            log_event(f"Port scan: {target}:{port} is OPEN")
        except:
            pass

def extended_port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["extended_ports"]
    open_ports = []
    def scan_port(port):
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    print(Fore.MAGENTA + f"[~] Initiating extended scan on {target}..." + Style.RESET_ALL)
    with ThreadPoolExecutor(max_workers=SETTINGS["max_threads"]) as executor:
        executor.map(scan_port, ports)
    for port in open_ports:
        print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
        log_event(f"Extended port scan: {target}:{port} is OPEN")

def get_ip():
    hostname = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] IP of {hostname}: {ip}" + Style.RESET_ALL)
        log_event(f"Resolved {hostname} to {ip}")
    except socket.error:
        print(Fore.RED + "[-] Invalid hostname." + Style.RESET_ALL)
        log_event(f"Failed to resolve {hostname}")

def http_headers():
    url = input(Fore.CYAN + "[>] Enter full URL (http://...): " + Style.RESET_ALL)
    try:
        r = requests.get(url)
        print(Fore.MAGENTA + "[~] HTTP Headers:" + Style.RESET_ALL)
        for k, v in r.headers.items():
            print(Fore.GREEN + f"{k}: {v}" + Style.RESET_ALL)
        log_event(f"Retrieved HTTP headers for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"HTTP headers error for {url}: {e}")

def reverse_ip():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP: {ip}" + Style.RESET_ALL)
        print(Fore.MAGENTA + "[~] Domains hosted (mock):" + Style.RESET_ALL)
        print(Fore.GREEN + "example.com\nsub.example.com" + Style.RESET_ALL)
        log_event(f"Reverse IP lookup for {domain}: {ip}")
    except:
        print(Fore.RED + "[-] Reverse IP Lookup failed." + Style.RESET_ALL)
        log_event(f"Reverse IP lookup failed for {domain}")

def dns_lookup():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        result = socket.gethostbyname_ex(domain)
        print(Fore.GREEN + f"[+] DNS Info: {result}" + Style.RESET_ALL)
        log_event(f"DNS lookup for {domain}: {result}")
    except:
        print(Fore.RED + "[-] DNS Lookup failed." + Style.RESET_ALL)
        log_event(f"DNS lookup failed for {domain}")

def traceroute():
    target = input(Fore.CYAN + "[>] Enter target: " + Style.RESET_ALL)
    try:
        if platform.system() == "Windows":
            os.system(f"tracert {target}")
        else:
            os.system(f"traceroute {target}")
        log_event(f"Traceroute performed for {target}")
    except:
        print(Fore.RED + "[-] Traceroute failed." + Style.RESET_ALL)
        log_event(f"Traceroute failed for {target}")

def whois_lookup():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        import whois
        data = whois.whois(domain)
        print(Fore.MAGENTA + "[~] WHOIS Data:" + Style.RESET_ALL)
        print(Fore.GREEN + str(data) + Style.RESET_ALL)
        log_event(f"WHOIS lookup for {domain}")
    except:
        print(Fore.RED + "[-] Install `python-whois` module." + Style.RESET_ALL)
        log_event(f"WHOIS lookup failed for {domain}: python-whois not installed")

def packet_sniffer():
    interface = input(Fore.CYAN + "[>] Enter interface (e.g., eth0): " + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        def process_packet(packet):
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                print(Fore.GREEN + f"[+] Packet: {src} -> {dst}" + Style.RESET_ALL)
                log_event(f"Sniffed packet: {src} -> {dst}")
        scapy.sniff(iface=interface, prn=process_packet, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event("Packet sniffer failed: scapy not installed")

def arp_spoof_detector():
    try:
        import scapy.all as scapy
        def detect_arp(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                print(Fore.RED + f"[!] ARP spoofing: {packet[scapy.ARP].psrc} claims {packet[scapy.ARP].hwsrc}" + Style.RESET_ALL)
                log_event(f"Detected ARP spoofing: {packet[scapy.ARP].psrc}")
        scapy.sniff(filter="arp", prn=detect_arp, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event("ARP spoof detector failed: scapy not installed")

def mac_address_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        arp = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            print(Fore.GREEN + f"[+] IP: {ip}, MAC: {received.hwsrc}" + Style.RESET_ALL)
            log_event(f"MAC address lookup: {ip} -> {received.hwsrc}")
    except:
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event(f"MAC address lookup failed for {ip}")

def bandwidth_monitor():
    print(Fore.MAGENTA + "[~] Monitoring bandwidth..." + Style.RESET_ALL)
    try:
        for _ in range(5):
            net_io = psutil.net_io_counters()
            print(Fore.GREEN + f"[+] Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB" + Style.RESET_ALL)
            log_event(f"Bandwidth: Sent {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            time.sleep(1)
    except:
        print(Fore.RED + "[-] Install `psutil` module." + Style.RESET_ALL)
        log_event("Bandwidth monitor failed: psutil not installed")

def ssl_certificate_check():
    url = input(Fore.CYAN + "[>] Enter URL (https://...): " + Style.RESET_ALL)
    try:
        hostname = urllib.parse.urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + f"[+] SSL Certificate: {cert['subject']}" + Style.RESET_ALL)
                log_event(f"SSL certificate checked for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"SSL certificate check failed for {url}: {e}")

def dns_enumeration():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(Fore.GREEN + f"[+] {record}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS enumeration: {domain} {record} -> {rdata}")
        except:
            pass

def network_interfaces():
    interfaces = netifaces.interfaces()
    print(Fore.MAGENTA + "[~] Network Interfaces:" + Style.RESET_ALL)
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                print(Fore.GREEN + f"[+] {iface}: {addr['addr']}" + Style.RESET_ALL)
                log_event(f"Network interface: {iface} -> {addr['addr']}")

def file_integrity_check():
    file_path = input(Fore.CYAN + "[>] Enter file path: " + Style.RESET_ALL)
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(Fore.GREEN + f"[+] SHA256: {file_hash}" + Style.RESET_ALL)
        log_event(f"File integrity check: {file_path} -> {file_hash}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File integrity check failed for {file_path}: {e}")

def vulnerability_scan():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Scanning vulnerabilities (mock)..." + Style.RESET_ALL)
    vulnerabilities = ["Open port 23 (Telnet)", "Weak SSL version detected"]
    for vuln in vulnerabilities:
        print(Fore.RED + f"[!] {vuln}" + Style.RESET_ALL)
        log_event(f"Vulnerability scan: {target} -> {vuln}")

def packet_injection_test():
    print(Fore.MAGENTA + "[~] Packet injection test (root required)." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        dest_ip = input(Fore.CYAN + "[>] Enter destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip)/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Packet sent." + Style.RESET_ALL)
        log_event(f"Packet injection test sent to {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` and run as root." + Style.RESET_ALL)
        log_event("Packet injection test failed")

def password_strength_checker():
    password = getpass.getpass(Fore.CYAN + "[>] Enter password: " + Style.RESET_ALL)
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[@#$%^&+=]", password):
        score += 1
    strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
    print(Fore.GREEN + f"[+] Password strength: {strength} (Score: {score}/5)" + Style.RESET_ALL)
    log_event(f"Password strength check: {strength}")

def network_traffic_analysis():
    print(Fore.MAGENTA + "[~] Analyzing traffic (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: TCP, UDP, ICMP" + Style.RESET_ALL)
    log_event("Network traffic analysis performed")

def firewall_rule_check():
    print(Fore.MAGENTA + "[~] Checking firewall (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Rules: Allow TCP 80, 443; Block UDP 53" + Style.RESET_ALL)
    log_event("Firewall rule check performed")

def os_fingerprinting():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Fingerprinting OS (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] OS: Linux/Windows (mock)" + Style.RESET_ALL)
    log_event(f"OS fingerprinting attempted on {target}")

def banner_grabbing():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    port = int(input(Fore.CYAN + "[>] Enter port: " + Style.RESET_ALL))
    try:
        s = socket.socket()
        s.settimeout(SETTINGS["timeout"])
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode()
        print(Fore.GREEN + f"[+] Banner: {banner}" + Style.RESET_ALL)
        log_event(f"Banner grabbed from {target}:{port}")
        s.close()
    except:
        print(Fore.RED + "[-] Banner grabbing failed." + Style.RESET_ALL)
        log_event(f"Banner grabbing failed for {target}:{port}")

def subnet_calculator():
    ip = input(Fore.CYAN + "[>] Enter IP (e.g., 192.168.1.0): " + Style.RESET_ALL)
    mask = int(input(Fore.CYAN + "[>] Enter mask bits (e.g., 24): " + Style.RESET_ALL))
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        print(Fore.GREEN + f"[+] Network: {network.network_address}/{mask}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hosts: {network.num_addresses - 2}" + Style.RESET_ALL)
        log_event(f"Subnet calculated for {ip}/{mask}")
    except:
        print(Fore.RED + "[-] Invalid IP or mask." + Style.RESET_ALL)
        log_event(f"Subnet calculation failed for {ip}/{mask}")

def geo_ip_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            print(Fore.GREEN + f"[+] Location: {data['city']}, {data['country']}" + Style.RESET_ALL)
            log_event(f"GeoIP lookup for {ip}: {data['city']}, {data['country']}")
        else:
            print(Fore.RED + "[-] GeoIP lookup failed." + Style.RESET_ALL)
            log_event(f"GeoIP lookup failed for {ip}")
    except:
        print(Fore.RED + "[-] GeoIP lookup error." + Style.RESET_ALL)
        log_event(f"GeoIP lookup error for {ip}")

def http_method_test():
    url = input(Fore.CYAN + "[>] Enter URL: " + Style.RESET_ALL)
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    for method in methods:
        try:
            r = requests.request(method, url)
            print(Fore.GREEN + f"[+] {method}: {r.status_code}" + Style.RESET_ALL)
            log_event(f"HTTP method test: {method} on {url} -> {r.status_code}")
        except:
            print(Fore.RED + f"[-] {method}: Failed" + Style.RESET_ALL)
            log_event(f"HTTP method test failed: {method} on {url}")

def dns_zone_transfer():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for ns in answers:
            ns = str(ns)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                print(Fore.GREEN + f"[+] Zone transfer from {ns}:" + Style.RESET_ALL)
                for name, rdata in zone.iterate_rdatas():
                    print(Fore.GREEN + f"{name}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer from {ns} for {domain}")
            except:
                print(Fore.RED + f"[-] Zone transfer failed for {ns}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer failed for {ns}")
    except:
        print(Fore.RED + "[-] DNS zone transfer failed." + Style.RESET_ALL)
        log_event(f"DNS zone transfer failed for {domain}")

def network_latency_test():
    target = input(Fore.CYAN + "[>] Enter target IP/hostname: " + Style.RESET_ALL)
    try:
        start = time.time()
        socket.create_connection((target, 80), timeout=SETTINGS["timeout"])
        latency = (time.time() - start) * 1000
        print(Fore.GREEN + f"[+] Latency: {latency:.2f} ms" + Style.RESET_ALL)
        log_event(f"Network latency test to {target}: {latency:.2f} ms")
    except:
        print(Fore.RED + "[-] Latency test failed." + Style.RESET_ALL)
        log_event(f"Network latency test failed for {target}")

def protocol_analyzer():
    print(Fore.MAGENTA + "[~] Analyzing protocols (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: HTTP, HTTPS, FTP, SSH" + Style.RESET_ALL)
    log_event("Protocol analysis performed")

def log_file_analyzer():
    log_file = os.path.join(CONFIG_DIR, SETTINGS["log_file"])
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        print(Fore.MAGENTA + "[~] Recent log entries:" + Style.RESET_ALL)
        for line in lines[-5:]:
            print(Fore.GREEN + f"[+] {line.strip()}" + Style.RESET_ALL)
        log_event("Log file analysis performed")
    except:
        print(Fore.RED + "[-] Log file not found." + Style.RESET_ALL)
        log_event("Log file analysis failed")

# -------------------- ETHICAL TOOLS --------------------
def ethical_dilemma_analyzer():
    print(Fore.MAGENTA + "[~] Ethical Dilemma Analyzer" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Network action: " + Style.RESET_ALL)
    target = input(Fore.CYAN + "[>] Target (IP/domain): " + Style.RESET_ALL)
    permission = input(Fore.CYAN + "[>] Explicit permission? (yes/no): " + Style.RESET_ALL).lower()
    result = "Ethical" if permission == "yes" else "Unethical: Requires permission"
    print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
    log_event(f"Ethical dilemma analysis: {action} on {target} -> {result}")

def decision_making_framework():
    print(Fore.MAGENTA + "[~] Decision-Making Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to evaluate: " + Style.RESET_ALL)
    criteria = ["Legality", "Consent", "Impact", "Necessity"]
    scores = {}
    for criterion in criteria:
        score = int(input(Fore.CYAN + f"[>] Score for {criterion} (1-5): " + Style.RESET_ALL))
        scores[criterion] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Proceed" if avg_score >= 3 else "Reconsider"
    print(Fore.GREEN + f"[+] Decision: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Decision-making framework: {action} -> {result}")

def principles_manager():
    print(Fore.MAGENTA + "[~] Ethical Principles Manager" + Style.RESET_ALL)
    principles = ["Respect for autonomy", "Non-maleficence", "Beneficence", "Justice"]
    print(Fore.GREEN + "[+] Principles: " + ", ".join(principles) + Style.RESET_ALL)
    new_principle = input(Fore.CYAN + "[>] Add principle (Enter to skip): " + Style.RESET_ALL)
    if new_principle:
        principles.append(new_principle)
        print(Fore.GREEN + f"[+] Added: {new_principle}" + Style.RESET_ALL)
        log_event(f"Added ethical principle: {new_principle}")

def compliance_checker():
    print(Fore.MAGENTA + "[~] Compliance Checker" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to check: " + Style.RESET_ALL)
    standards = ["GDPR", "HIPAA", "PCI-DSS"]
    results = []
    for standard in standards:
        compliant = input(Fore.CYAN + f"[>] Compliant with {standard}? (yes/no): " + Style.RESET_ALL).lower()
        results.append(f"{standard}: {'Compliant' if compliant == 'yes' else 'Non-compliant'}")
    print(Fore.GREEN + "[+] Results: " + "; ".join(results) + Style.RESET_ALL)
    log_event(f"Compliance check for {action}: {'; '.join(results)}")

def scenario_generator():
    print(Fore.MAGENTA + "[~] Ethical Scenario Generator" + Style.RESET_ALL)
    scenarios = [
        "Unauthorized port scan on a corporate network",
        "Packet sniffing on a public Wi-Fi",
        "Bypassing authentication on a test server"
    ]
    scenario = random.choice(scenarios)
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Generated scenario: {scenario}")

def decision_tree_builder():
    print(Fore.MAGENTA + "[~] Decision Tree Builder" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to analyze: " + Style.RESET_ALL)
    tree = {"Action": action, "Steps": []}
    while True:
        step = input(Fore.CYAN + "[>] Add step (Enter to finish): " + Style.RESET_ALL)
        if not step:
            break
        tree["Steps"].append(step)
    print(Fore.GREEN + f"[+] Tree: {json.dumps(tree, indent=2)}" + Style.RESET_ALL)
    log_event(f"Built decision tree for {action}")

# -------------------- UTILITY TOOLS --------------------
def user_signup():
    print(Fore.MAGENTA + "[~] Register New Node" + Style.RESET_ALL)
    username = input(Fore.CYAN + "[>] Enter NETMASK: " + Style.RESET_ALL)
    password = getpass.getpass(Fore.CYAN + "[>] Enter KEYCODE: " + Style.RESET_ALL)
    with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
        users_data = json.load(f)
    if any(user['username'] == username for user in users_data['users']):
        print(Fore.RED + "[-] NETMASK already exists." + Style.RESET_ALL)
        log_event(f"Sign-up failed: {username} already exists")
    else:
        user_id = str(uuid.uuid4())
        users_data['users'].append({"id": user_id, "username": username, "password": hashlib.sha256(password.encode()).hexdigest(), "role": "user"})
        with open(os.path.join(CONFIG_DIR, "users.json"), "w") as f:
            json.dump(users_data, f, indent=4)
        print(Fore.GREEN + "[+] Node registered successfully." + Style.RESET_ALL)
        log_event(f"User signed up: {username}")

def automated_backup():
    print(Fore.MAGENTA + "[~] Initiating backup..." + Style.RESET_ALL)
    backup_dir = os.path.join(CONFIG_DIR, "backups")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for file_name in CONFIG_FILES.keys():
        src = os.path.join(CONFIG_DIR, file_name)
        dst = os.path.join(backup_dir, f"{file_name}.{timestamp}.bak")
        with open(src, "r") as f:
            data = f.read()
        with open(dst, "w") as f:
            f.write(data)
        print(Fore.GREEN + f"[+] Backed up {file_name} to {dst}" + Style.RESET_ALL)
        log_event(f"Backed up {file_name} to {dst}")

def multi_language_support():
    print(Fore.MAGENTA + "[~] Multi-Language Interface" + Style.RESET_ALL)
    languages = {"en": "English", "es": "Spanish", "fr": "French"}
    lang = input(Fore.CYAN + f"[>] Select language ({', '.join(languages.values())}): " + Style.RESET_ALL).lower()
    lang_code = next((code for code, name in languages.items() if name.lower() == lang), "en")
    try:
        from translate import Translator
        translator = Translator(to_lang=lang_code)
        message = translator.translate("Network scan completed")
        print(Fore.GREEN + f"[+] Translated: {message}" + Style.RESET_ALL)
        log_event(f"Translated message to {lang_code}")
    except:
        print(Fore.RED + "[-] Install `python-translate` module." + Style.RESET_ALL)
        log_event("Multi-language support failed: python-translate not installed")

def report_generator():
    print(Fore.MAGENTA + "[~] Generating Report" + Style.RESET_ALL)
    report_type = input(Fore.CYAN + "[>] Type (summary/detailed): " + Style.RESET_ALL).lower()
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        report_file = os.path.join(CONFIG_DIR, f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_file, "w") as f:
            f.write("HUTNTER Report\n")
            f.write(f"Generated: {datetime.datetime.now()}\n")
            f.write(f"Type: {report_type}\n\n")
            if report_type == "summary":
                f.write(f"Total Logs: {len(logs)}\n")
            else:
                for log in logs:
                    f.write(log)
        print(Fore.GREEN + f"[+] Report saved: {report_file}" + Style.RESET_ALL)
        log_event(f"Generated {report_type} report: {report_file}")
    except:
        print(Fore.RED + "[-] Report generation failed." + Style.RESET_ALL)
        log_event("Report generation failed")

# -------------------- HELP MENU --------------------
def help_menu():
    print(Fore.YELLOW + "\n===== NEON GRID COMMAND INDEX =====" + Style.RESET_ALL)
    print(Fore.CYAN + """
    1. Ping Host                - Send ICMP probes to check host status
    2. Port Scanner             - Scan common ports for open services
    3. Get IP                   - Resolve domain to IP address
    4. HTTP Headers             - Fetch server response headers
    5. Reverse IP               - Lookup domains on IP (mocked)
    6. DNS Lookup               - Query DNS records
    7. Traceroute               - Trace packet route to target
    8. WHOIS                 - Fetch domain registration data
    9. Extended Port Scan      - Scan ports 1-1000
    10. Packet Sniffer          - Capture network packets (scapy)
    11. ARP Spoof Detector      - Detect ARP spoofing attacks
    12. MAC Address Lookup      - Find MAC address for IP (scapy)
    13. Bandwidth Monitor       - Track network usage
    14. SSL Certificate Check   - Verify SSL certificate details
    15. DNS Enumeration        - Enumerate DNS records (A, MX, etc.)
    16. Network Interfaces      - List network adapters
    17. File Integrity          - Compute SHA256 hash of file
    18. Vulnerability Scan      - Basic vuln check (mock)
    19. Packet Injection        - Send test packet (root, scapy)
    20. Password Strength       - Evaluate password strength
    21. Network Traffic         - Analyze traffic (mock)
    22. Firewall Rules          - Check firewall (mock)
    23. OS Fingerprint          - Detect OS (mock)
    24. Banner Grab             - Fetch service banners
    25. Subnet Calculator       - Compute subnet details
    26. GeoIP Lookup            - Locate IP geographically
    27. HTTP Method Test        - Test HTTP methods on URL
    28. DNS Zone Transfer       - Attempt DNS zone transfer
    29. Network Latency         - Measure latency to target
    30. Protocol Analyzer       - Analyze protocols (mock)
    31. Log File Analyzer           - Review recent logs
    32. Session Sign-Up         - Register new user
    33. Ethical Dilemma         - Analyze ethical concerns
    34. Decision Framework      - Evaluate actions ethically
    35. Principles Manager     - Manage ethical principles
    36. Compliance Check        - Verify compliance (GDPR, etc.)
    37. Scenario Generator      - Create ethical scenarios
    38. Decision Tree           - Build decision trees
    39. Automated Backup        - Backup config files
    40. Multi-Language          - Translate interface
    41. Report Generator        - Create log reports
    42. Exit                   - Disconnect from CLI

    Admin Tools:
    - Launch `dashboard.py` for admin controls
    - URL: http://localhost:5000
    - Features: Node management, DDoS whitelist, metrics, exclusive tools
    - Default: NETMASK@Ethan, KEYCODE@Admin

    Commands: h, help - Show this index
    """ + Style.RESET_ALL)

# -------------------- MENU --------------------
def menu(user_session):
    while True:
        banner()
        print(Fore.MAGENTA + f"[NODE: {user_session['username']}] [ROLE: {user_session['role'].upper()}]" + Style.RESET_ALL)
        print(Fore.YELLOW + "\n===== NEON GRID COMMANDMENT =====" + Style.RESET_ALL)
        print(Fore.CYAN + """
[NETWORK TOOLS]
1. Ping Host                2. Port Scanner            3. Get IP
4. HTTP Headers             5. Reverse IP              6. DNS Lookup
7. Traceroute               8. WHOIS                    9. Extended Scan
10. Packet Sniffer          11. ARP Spoofing        12. MAC Lookup
13. Bandwidth Monitor       14. SSL Certificate      15. DNS Enumeration
16. Network Interfaces      17. File Integrity       18. Vulnerability Scanner
19. Packet Injection        20. Password Check       21. Traffic Analysis
22. Firewall Rules          23. OS Fingerprint       24. Banner Grab
25. Subnet Calculator       26. GeoIP Lookup        27. HTTP Methods
28. DNS Zone Transfer      29. Latency Test      30. Protocol Analysis
31. Log Analyzer
[ETHICAL TOOLS]
33. Ethical Dilemma         34. Decision Framework    35. Principles
36. Compliance             37. Scenarios            38. Decision Tree
[UTILITY TOOLS]
32. User Sign-Up          39. Auto Backup           40. Multi-Language
41. Report Generator
[CONTROL]
42. Disconnect              h. Grid Index
        """ + Style.RESET_ALL)
        choice = input(Fore.GREEN + "[>] Select: " + Style.RESET_ALL).strip().lower()
        if choice == "1":
            ping_host()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            get_ip()
        elif choice == "4":
            http_headers()
        elif choice == "5":
            reverse_ip()
        elif choice == "6":
            dns_lookup()
        elif choice == "7":
            traceroute()
        elif choice == "8":
            whois_lookup()
        elif choice == "9":
            extended_port_scan()
        elif choice == "10":
            packet_sniffer()
        elif choice == "11":
            arp_spoof_detector()
        elif choice == "12":
            mac_address_lookup()
        elif choice == "13":
            bandwidth_monitor()
        elif choice == "14":
            ssl_certificate_check()
        elif choice == "15":
            dns_enumeration()
        elif choice == "16":
            network_interfaces()
        elif choice == "17":
            file_integrity_check()
        elif choice == "18":
            vulnerability_scan()
        elif choice == "19":
            packet_injection_test()
        elif choice == "20":
            password_strength_checker()
        elif choice == "21":
            network_traffic_analysis()
        elif choice == "22":
            firewall_rule_check()
        elif choice == "23":
            os_fingerprinting()
        elif choice == "24":
            banner_grabbing()
        elif choice == "25":
            subnet_calculator()
        elif choice == "26":
            geo_ip_lookup()
        elif choice == "27":
            http_method_test()
        elif choice == "28":
            dns_zone_transfer()
        elif choice == "29":
            network_latency_test()
        elif choice == "30":
            protocol_analyzer()
        elif choice == "31":
            log_file_analyzer()
        elif choice == "32":
            user_signup()
        elif choice == "33":
            ethical_dilemma_analyzer()
        elif choice == "34":
            decision_making()
            framework()
        elif choice == "35":
            principles_manager()
        elif choice == "36":
            compliance_checker()
        elif choice == "37':
            scenario_generator()
        elif choice == "38":
            decision_tree_builder()
        elif choice == "39":
            automated_backup()
        elif choice == "40":
            multi_language_support()
        elif choice == "41":
            report_generator()
        elif choice == "42":
            print(Fore.RED + "[!] Disconnecting from NEON GRID..." + Style.RESET_ALL)
            log_event(f"{user_session['role'].capitalize()} {user_session['username']} disconnected")
            break
        elif choice in ["h", "n"]:
            help_menu()
        else:
            print(Fore.RED + "[!] Invalid command. Check grid index (h)." + Style.RESET_ALL)
            log_event("Invalid command selected")
        input(Fore.CYAN + "[>] Press Enter to continue..." + Style.RESET_ALL)

# -------------------- RUN --------------------
if __name__ == "__main__":
    try:
        user_session = user_login()
        menu(user_session)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Grid interrupted by user." + Style.RESET_ALL)
        log_event("Hutnter interrupted by user")
        sys.exit(0)
