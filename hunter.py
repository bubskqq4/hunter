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
import base64
import paramiko
import smtplib
import email.mime.text
import shlex
import xml.etree.ElementTree as ET
import dns.resolver
import psutil
import netifaces
import ipaddress
import uuid
import random
import logging
import argparse
import csv
import traceback
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from pyfiglet import Figlet
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from translate import Translator
import pyotp
import qrcode
from cryptography.fernet import Fernet
from ftplib import FTP
import nmap
import whois
import scapy.all as scapy

init()

# -------------------- SETUP --------------------
CONFIG_DIR = "config"
LOG_FILE = "hutnter.log"
CONFIG_FILES = {
    "ports.json": {"common_ports": [21, 22, 23, 25, 53, 80, 443, 8080], "extended_ports": list(range(1, 1001))},
    "settings.json": {
        "timeout": 0.5,
        "max_threads": 50,
        "log_file": LOG_FILE,
        "ddos_threshold": 100,
        "language": "en",
        "theme": "cyberpunk",
        "report_format": "txt"
    },
    "whitelist.json": {"allowed_ips": []},
    "users.json": {"users": [{"id": str(uuid.uuid4()), "username": "Ethan", "password": hashlib.sha256("Admin".encode()).hexdigest(), "role": "admin", "otp_secret": pyotp.random_base32()}]}
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

# Setup logging
logging.basicConfig(
    filename=os.path.join(CONFIG_DIR, LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

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
    f = Figlet(font="slant")
    print(Fore.MAGENTA + f.renderText("HUTNTER") + Style.RESET_ALL)
    print(Fore.CYAN + "          NEON GRID DOMINATOR v2.0" + Style.RESET_ALL)
    print(Fore.GREEN + LEGAL + Style.RESET_ALL)

# -------------------- LOGGING --------------------
def log_event(message, level="INFO"):
    levels = {"INFO": logging.INFO, "ERROR": logging.ERROR, "WARNING": logging.WARNING}
    logging.log(levels.get(level, logging.INFO), message)
    print(Fore.CYAN + f"[*] {message}" + Style.RESET_ALL)

# -------------------- USER LOGIN --------------------
def user_login():
    banner()
    print(Fore.MAGENTA + "=== ACCESS THE NEON GRID ===" + Style.RESET_ALL)
    while True:
        username = input(Fore.CYAN + "[NETMASK] Enter username: " + Style.RESET_ALL).strip()
        password = getpass.getpass(Fore.CYAN + "[KEYCODE] Enter password: " + Style.RESET_ALL)
        with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
            users_data = json.load(f)
        for user in users_data['users']:
            if user['username'] == username and user['password'] == hashlib.sha256(password.encode()).hexdigest():
                # Two-Factor Authentication
                totp = pyotp.TOTP(user['otp_secret'])
                otp = input(Fore.CYAN + "[2FA] Enter OTP: " + Style.RESET_ALL)
                if totp.verify(otp):
                    log_event(f"{user['role'].capitalize()} login successful: {username}")
                    return {"id": user['id'], "username": username, "role": user['role'], "otp_secret": user['otp_secret']}
                else:
                    print(Fore.RED + "[-] Invalid OTP." + Style.RESET_ALL)
                    log_event(f"OTP verification failed: {username}", "ERROR")
        print(Fore.RED + "[-] Invalid NETMASK or KEYCODE. Retry." + Style.RESET_ALL)
        log_event(f"Login failed: {username}", "ERROR")
        print(Fore.CYAN + "[!] Register via option 32 or run dashboard.py for sign-up." + Style.RESET_ALL)
        input(Fore.CYAN + "[>] Press Enter to retry..." + Style.RESET_ALL)
        banner()

# -------------------- NEW FEATURES --------------------
def generate_otp_qr(user):
    totp = pyotp.TOTP(user['otp_secret'])
    uri = totp.provisioning_uri(name=user['username'], issuer_name="Hutnter")
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii()
    print(Fore.GREEN + "[+] Scan this QR code with your 2FA app." + Style.RESET_ALL)
    log_event(f"Generated OTP QR for {user['username']}")

def encrypt_file():
    file_path = input(Fore.CYAN + "[>] File to encrypt: " + Style.RESET_ALL)
    key = Fernet.generate_key()
    fernet = Fernet(key)
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(file_path + ".enc", "wb") as f:
            f.write(encrypted)
        with open(file_path + ".key", "wb") as f:
            f.write(key)
        print(Fore.GREEN + f"[+] Encrypted to {file_path}.enc. Key saved to {file_path}.key" + Style.RESET_ALL)
        log_event(f"Encrypted file: {file_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File encryption failed: {e}", "ERROR")

def decrypt_file():
    file_path = input(Fore.CYAN + "[>] Encrypted file: " + Style.RESET_ALL)
    key_file = input(Fore.CYAN + "[>] Key file: " + Style.RESET_ALL)
    try:
        with open(key_file, "rb") as f:
            key = f.read()
        fernet = Fernet(key)
        with open(file_path, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        with open(file_path.replace(".enc", ".dec"), "wb") as f:
            f.write(decrypted)
        print(Fore.GREEN + f"[+] Decrypted to {file_path.replace('.enc', '.dec')}" + Style.RESET_ALL)
        log_event(f"Decrypted file: {file_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File decryption failed: {e}", "ERROR")

def ssh_bruteforce():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    username = input(Fore.CYAN + "[>] Username: " + Style.RESET_ALL)
    wordlist = input(Fore.CYAN + "[>] Wordlist path: " + Style.RESET_ALL)
    try:
        with open(wordlist, "r") as f:
            passwords = f.readlines()
        for password in passwords[:10]:  # Limit for safety
            password = password.strip()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=username, password=password, timeout=5)
                print(Fore.GREEN + f"[+] Success: {username}:{password}" + Style.RESET_ALL)
                log_event(f"SSH brute-force success: {target} {username}:{password}")
                ssh.close()
                break
            except:
                print(Fore.RED + f"[-] Failed: {password}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"SSH brute-force failed: {e}", "ERROR")

def email_spoof_test():
    sender = input(Fore.CYAN + "[>] Spoofed sender email: " + Style.RESET_ALL)
    recipient = input(Fore.CYAN + "[>] Recipient email: " + Style.RESET_ALL)
    subject = input(Fore.CYAN + "[>] Subject: " + Style.RESET_ALL)
    body = input(Fore.CYAN + "[>] Body: " + Style.RESET_ALL)
    smtp_server = input(Fore.CYAN + "[>] SMTP server: " + Style.RESET_ALL)
    try:
        msg = email.mime.text.MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient
        with smtplib.SMTP(smtp_server, 25) as server:
            server.sendmail(sender, recipient, msg.as_string())
        print(Fore.GREEN + "[+] Email sent successfully." + Style.RESET_ALL)
        log_event(f"Email spoof test sent to {recipient}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Email spoof test failed: {e}", "ERROR")

def nmap_scan():
    target = input(Fore.CYAN + "[>] Target IP/hostname: " + Style.RESET_ALL)
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV -O")
        for host in nm.all_hosts():
            print(Fore.MAGENTA + f"[~] Host: {host} ({nm[host].hostname()})" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] State: {nm[host].state()}" + Style.RESET_ALL)
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(Fore.GREEN + f"[+] Port {port}/{proto}: {state} ({service})" + Style.RESET_ALL)
            if 'osmatch' in nm[host]:
                for os in nm[host]['osmatch']:
                    print(Fore.GREEN + f"[+] OS: {os['name']} ({os['accuracy']}%)" + Style.RESET_ALL)
        log_event(f"Nmap scan completed for {target}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Nmap scan failed: {e}", "ERROR")

def ftp_anonymous_login():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    try:
        ftp = FTP(target)
        ftp.login()
        print(Fore.GREEN + "[+] Anonymous login successful." + Style.RESET_ALL)
        log_event(f"FTP anonymous login succeeded: {target}")
        ftp.quit()
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"FTP anonymous login failed: {e}", "ERROR")

def network_map():
    target = input(Fore.CYAN + "[>] Target network (e.g., 192.168.1.0/24): " + Style.RESET_ALL)
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn")
        hosts = []
        for host in nm.all_hosts():
            hosts.append({"ip": host, "state": nm[host].state()})
        print(Fore.MAGENTA + "[~] Network Map:" + Style.RESET_ALL)
        for host in hosts:
            print(Fore.GREEN + f"[+] {host['ip']}: {host['state']}" + Style.RESET_ALL)
        log_event(f"Network map generated for {target}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Network map failed: {e}", "ERROR")

def wifi_password_retrieval():
    if platform.system() != "Windows":
        print(Fore.RED + "[-] This feature is Windows-only." + Style.RESET_ALL)
        return
    try:
        data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
        profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
        for profile in profiles:
            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8').split('\n')
            passwords = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
            print(Fore.GREEN + f"[+] Profile: {profile}, Password: {passwords[0] if passwords else 'None'}" + Style.RESET_ALL)
            log_event(f"WiFi password retrieved for profile: {profile}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"WiFi password retrieval failed: {e}", "ERROR")

def system_info():
    print(Fore.MAGENTA + "[~] System Information:" + Style.RESET_ALL)
    info = {
        "OS": platform.system(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Architecture": platform.machine(),
        "CPU": psutil.cpu_count(logical=True),
        "Memory": f"{psutil.virtual_memory().total / (1024**3):.2f} GB"
    }
    for key, value in info.items():
        print(Fore.GREEN + f"[+] {key}: {value}" + Style.RESET_ALL)
    log_event("System information retrieved")

def generate_report_pdf():
    report_type = input(Fore.CYAN + "[>] Report type (summary/detailed): " + Style.RESET_ALL).lower()
    output_file = os.path.join(CONFIG_DIR, f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph("HUTNTER Report", styles['Title']))
        story.append(Paragraph(f"Generated: {datetime.datetime.now()}", styles['Normal']))
        story.append(Paragraph(f"Type: {report_type}", styles['Normal']))
        story.append(Spacer(1, 12))
        if report_type == "summary":
            story.append(Paragraph(f"Total Logs: {len(logs)}", styles['Normal']))
        else:
            for log in logs:
                story.append(Paragraph(log.strip(), styles['Normal']))
        doc.build(story)
        print(Fore.GREEN + f"[+] PDF report saved: {output_file}" + Style.RESET_ALL)
        log_event(f"Generated PDF report: {output_file}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"PDF report generation failed: {e}", "ERROR")

def real_time_monitor():
    print(Fore.MAGENTA + "[~] Real-Time Network Monitor (Press Ctrl+C to stop)" + Style.RESET_ALL)
    try:
        while True:
            net_io = psutil.net_io_counters()
            print(Fore.GREEN + f"[+] Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB" + Style.RESET_ALL)
            log_event(f"Real-time monitor: Sent {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Monitoring stopped." + Style.RESET_ALL)
        log_event("Real-time monitor stopped")

# -------------------- EXISTING TOOLS (ENHANCED) --------------------
def ping_host():
    target = input(Fore.CYAN + "[>] Target host/IP: " + Style.RESET_ALL)
    count = int(input(Fore.CYAN + "[>] Ping count (default 4): " + Style.RESET_ALL) or 4)
    try:
        cmd = f"ping -c {count} {target}" if platform.system() != "Windows" else f"ping -n {count} {target}"
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT).decode()
        print(Fore.GREEN + f"[+] {output}" + Style.RESET_ALL)
        log_event(f"Pinged {target}: Success")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] {e.output.decode()}" + Style.RESET_ALL)
        log_event(f"Ping failed: {target}", "ERROR")

def port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    ports = input(Fore.CYAN + "[>] Ports (comma-separated or 'common'): " + Style.RESET_ALL)
    ports = PORTS_CONFIG["common_ports"] if ports.lower() == "common" else [int(p) for p in ports.split(",")]
    print(Fore.MAGENTA + f"[~] Scanning {target}..." + Style.RESET_ALL)
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            service = socket.getservbyport(port, "tcp")
            print(Fore.GREEN + f"[+] Port {port} is OPEN ({service})" + Style.RESET_ALL)
            s.close()
            log_event(f"Port scan: {target}:{port} is OPEN")
        except:
            pass

def extended_port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    start_port = int(input(Fore.CYAN + "[>] Start port: " + Style.RESET_ALL))
    end_port = int(input(Fore.CYAN + "[>] End port: " + Style.RESET_ALL))
    ports = range(start_port, end_port + 1)
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
        try:
            service = socket.getservbyport(port, "tcp")
            print(Fore.GREEN + f"[+] Port {port} is OPEN ({service})" + Style.RESET_ALL)
            log_event(f"Extended port scan: {target}:{port} is OPEN")
        except:
            print(Fore.GREEN + f"[+] Port {port} is OPEN (Unknown service)" + Style.RESET_ALL)
            log_event(f"Extended port scan: {target}:{port} is OPEN")

def get_ip():
    hostname = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] IP of {hostname}: {ip}" + Style.RESET_ALL)
        log_event(f"Resolved {hostname} to {ip}")
    except socket.error as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Failed to resolve {hostname}: {e}", "ERROR")

def http_headers():
    url = input(Fore.CYAN + "[>] Enter full URL (http://...): " + Style.RESET_ALL)
    try:
        r = requests.get(url, timeout=10)
        print(Fore.MAGENTA + "[~] HTTP Headers:" + Style.RESET_ALL)
        for k, v in r.headers.items():
            print(Fore.GREEN + f"{k}: {v}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Status Code: {r.status_code}" + Style.RESET_ALL)
        log_event(f"Retrieved HTTP headers for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"HTTP headers error for {url}: {e}", "ERROR")

def reverse_ip():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        domains = response.text.split("\n")
        print(Fore.MAGENTA + "[~] Domains hosted:" + Style.RESET_ALL)
        for domain in domains:
            if domain:
                print(Fore.GREEN + f"[+] {domain}" + Style.RESET_ALL)
        log_event(f"Reverse IP lookup for {ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Reverse IP lookup failed: {e}", "ERROR")

def dns_lookup():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        result = socket.gethostbyname_ex(domain)
        print(Fore.MAGENTA + "[~] DNS Info:" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hostname: {result[0]}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Aliases: {result[1]}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] IPs: {result[2]}" + Style.RESET_ALL)
        log_event(f"DNS lookup for {domain}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"DNS lookup failed: {e}", "ERROR")

def traceroute():
    target = input(Fore.CYAN + "[>] Enter target: " + Style.RESET_ALL)
    try:
        cmd = f"traceroute {target}" if platform.system() != "Windows" else f"tracert {target}"
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT).decode()
        print(Fore.GREEN + f"[+] {output}" + Style.RESET_ALL)
        log_event(f"Traceroute performed for {target}")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] {e.output.decode()}" + Style.RESET_ALL)
        log_event(f"Traceroute failed: {e}", "ERROR")

def whois_lookup():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        data = whois.whois(domain)
        print(Fore.MAGENTA + "[~] WHOIS Data:" + Style.RESET_ALL)
        for key, value in data.items():
            print(Fore.GREEN + f"[+] {key}: {value}" + Style.RESET_ALL)
        log_event(f"WHOIS lookup for {domain}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"WHOIS lookup failed: {e}", "ERROR")

def packet_sniffer():
    interface = input(Fore.CYAN + "[>] Enter interface (e.g., eth0): " + Style.RESET_ALL)
    count = int(input(Fore.CYAN + "[>] Packet count (default 10): " + Style.RESET_ALL) or 10)
    try:
        def process_packet(packet):
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                print(Fore.GREEN + f"[+] Packet: {src} -> {dst} (Proto: {proto})" + Style.RESET_ALL)
                log_event(f"Sniffed packet: {src} -> {dst}")
        scapy.sniff(iface=interface, prn=process_packet, count=count)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Packet sniffer failed: {e}", "ERROR")

def arp_spoof_detector():
    try:
        def detect_arp(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                print(Fore.RED + f"[!] ARP spoofing: {packet[scapy.ARP].psrc} claims {packet[scapy.ARP].hwsrc}" + Style.RESET_ALL)
                log_event(f"Detected ARP spoofing: {packet[scapy.ARP].psrc}")
        scapy.sniff(filter="arp", prn=detect_arp, count=10)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"ARP spoof detector failed: {e}", "ERROR")

def mac_address_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
    try:
        arp = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            print(Fore.GREEN + f"[+] IP: {ip}, MAC: {received.hwsrc}" + Style.RESET_ALL)
            log_event(f"MAC address lookup: {ip} -> {received.hwsrc}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"MAC address lookup failed: {e}", "ERROR")

def bandwidth_monitor():
    duration = int(input(Fore.CYAN + "[>] Duration (seconds, default 10): " + Style.RESET_ALL) or 10)
    print(Fore.MAGENTA + "[~] Monitoring bandwidth..." + Style.RESET_ALL)
    try:
        start = time.time()
        while time.time() - start < duration:
            net_io = psutil.net_io_counters()
            print(Fore.GREEN + f"[+] Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB" + Style.RESET_ALL)
            log_event(f"Bandwidth: Sent {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            time.sleep(1)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Bandwidth monitor failed: {e}", "ERROR")

def ssl_certificate_check():
    url = input(Fore.CYAN + "[>] Enter URL (https://...): " + Style.RESET_ALL)
    try:
        hostname = urllib.parse.urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.MAGENTA + "[~] SSL Certificate:" + Style.RESET_ALL)
                for key, value in cert.items():
                    print(Fore.GREEN + f"[+] {key}: {value}" + Style.RESET_ALL)
                log_event(f"SSL certificate checked for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"SSL certificate check failed: {e}", "ERROR")

def dns_enumeration():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    print(Fore.MAGENTA + "[~] Enumerating DNS records..." + Style.RESET_ALL)
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(Fore.GREEN + f"[+] {record}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS enumeration: {domain} {record} -> {rdata}")
        except:
            pass

def network_interfaces():
    print(Fore.MAGENTA + "[~] Network Interfaces:" + Style.RESET_ALL)
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                print(Fore.GREEN + f"[+] {iface}: {addr['addr']} (Netmask: {addr['netmask']})" + Style.RESET_ALL)
                log_event(f"Network interface: {iface} -> {addr['addr']}")

def file_integrity_check():
    file_path = input(Fore.CYAN + "[>] File path: " + Style.RESET_ALL)
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(Fore.GREEN + f"[+] SHA256: {file_hash}" + Style.RESET_ALL)
        log_event(f"File integrity check: {file_path} -> {file_hash}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File integrity check failed: {e}", "ERROR")

def vulnerability_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV --script=vuln")
        for host in nm.all_hosts():
            print(Fore.MAGENTA + f"[~] Host: {host}" + Style.RESET_ALL)
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(Fore.GREEN + f"[+] Port {port}/{proto}: {state} ({service})" + Style.RESET_ALL)
                    if 'script' in nm[host][proto][port]:
                        for script, output in nm[host][proto][port]['script'].items():
                            print(Fore.RED + f"[!] Vulnerability: {script}\n{output}" + Style.RESET_ALL)
                            log_event(f"Vulnerability scan: {target} -> {script}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Vulnerability scan failed: {e}", "ERROR")

def packet_injection_test():
    print(Fore.MAGENTA + "[~] Packet injection test (root required)." + Style.RESET_ALL)
    try:
        dest_ip = input(Fore.CYAN + "[>] Destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip)/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Packet sent." + Style.RESET_ALL)
        log_event(f"Packet injection test sent to {dest_ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Packet injection failed: {e}", "ERROR")

def password_strength_checker():
    password = getpass.getpass(Fore.CYAN + "[>] Password: " + Style.RESET_ALL)
    score = 0
    checks = [
        (len(password) >= 8, "Length >= 8"),
        (re.search(r"[A-Z]", password), "Uppercase"),
        (re.search(r"[a-z]", password), "Lowercase"),
        (re.search(r"[0-9]", password), "Numbers"),
        (re.search(r"[@#$%^&+=]", password), "Special chars")
    ]
    for condition, desc in checks:
        if condition:
            score += 1
            print(Fore.GREEN + f"[+] {desc}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[-] {desc}" + Style.RESET_ALL)
    strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
    print(Fore.GREEN + f"[+] Password strength: {strength} (Score: {score}/5)" + Style.RESET_ALL)
    log_event(f"Password strength check: {strength}")

def network_traffic_analysis():
    interface = input(Fore.CYAN + "[>] Interface: " + Style.RESET_ALL)
    try:
        def process_packet(packet):
            if packet.haslayer(scapy.IP):
                proto = packet[scapy].IP[0].proto
                src = packet[scapy].IP[0].src
                dst = packet[scapy].IP[0].dst
                print(Fore.GREEN + f"[+] {src} -> {dst} (Proto: {proto})" + Style.RESET_ALL)
                log_event(f"Traffic analysis: {src} -> {dst}")
        scapy.sniff(iface=interface, prn=process_packet, count=5)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Traffic analysis failed: {e}", "ERROR")

def firewall_rule_check():
    print(Fore.MAGENTA + "[~] Checking firewall rules (mock)..." + Style.RESET_ALL)
    rules = ["Allow TCP 80", "Allow TCP 443", "Block UDP 53"]
    for rule in rules:
        print(Fore.GREEN + f"[+] {rule}" + Style.RESET_ALL)
    log_event("Firewall rule check completed")

def os_fingerprinting():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    try:
        nm = nmap()
        nm.scan(target, arguments="-O")
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                for os in nm[host]['osmatch']:
                    print(Fore.GREEN + f"[+] OS: {os['name']} ({os['accuracy']}%)" + Style.RESET_ALL)
                    log_event(f"OS fingerprinting: {target} -> {os['name']}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"OS fingerprinting failed: {e}", "ERROR")

def banner_grabbing():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    target = input(Fore.RESET + C"[>] Target IP: " + Style.RESET_ALL)
    port = int(input(Fore.CYAN + "[>] Enter port: " + Style.RESET_ALL))
    try:
        s = socket.socket()
        s.settimeout(SETTINGS["timeout"])
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        print(Fore.GREEN + f"[+] Banner: {banner}" + Style.RESET_ALL)
        log_event(f"Banner grabbed: {target}:{port}")
        s.close()
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Banner grabbing failed: {e}", "ERROR")

def subnet_calculator():
    ip = input(Fore.CYAN + "[>] Enter IP (e.g., 192.168.1.0): " + Style.RESET_ALL)
    mask = int(input(Fore.RESET + C"[>] Enter mask bits (e.g., 24): " + Style.RESET_ALL))
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        print(Fore.GREEN + f"[+] Network: {network.network_address}/{mask}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hosts: {network.num_addresses - 2}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Broadcast: {network.broadcast_address}" + Style.RESET_ALL)
        log_event(f"Subnet calculated: {ip}/{mask}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Subnet calculation failed: {e}", "ERROR")

def geo_ip_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            print(Fore.MAGENTA + "[~] GeoIP Info:" + Style.RESET_ALL)
            for key in ['city', 'regionName', 'country', 'lat', 'lon', 'isp']:
                print(Fore.GREEN + f"[+] {key}: {data[key]}" + Style.RESET_ALL)
            log_event(f"GeoIP lookup: {ip} -> {data['city']}, {data['country']}")
        else:
            raise Exception("GeoIP lookup failed")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"GeoIP lookup failed: {e}", "ERROR")

def http_method_test():
    url = input(Fore.CYAN + "[>] Enter URL: " + Style.RESET_ALL)
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    print(Fore.MAGENTA + "[~] Testing HTTP methods..." + Style.RESET_ALL)
    for method in methods:
        try:
            r = requests.request(method, url, timeout=5)
            print(Fore.GREEN + f"[+] {method}: {r.status_code}" + Style.RESET_ALL)
            log_event(f"HTTP method test: {method} -> {r.status_code}")
        except Exception as e:
            print(Fore.RED + f"[-] {method}: {e}" + Style.RESET_ALL)
            log_event(f"HTTP method test failed: {method} - {e}", "ERROR")

def dns_zone_transfer():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for ns in answers:
            ns = str(ns)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                print(Fore.MAGENTA + f"[~] Zone transfer from {ns}:" + Style.RESET_ALL)
                for name, rdata in zone.iterate_rdatas():
                    print(Fore.GREEN + f"[+] {name}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer: {ns}")
            except:
                print(Fore.RED + f"[-] Zone transfer failed: {ns}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer failed: {ns}", "ERROR")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"DNS zone transfer failed: {e}", "ERROR")

def network_latency_test():
    target = input(Fore.CYAN + "[>] Target IP/hostname: " + Style.RESET_ALL)
    count = int(input(Fore.CYAN + "[>] Test count (default 5): " + Style.RESET_ALL) or 5)
    latencies = []
    try:
        for _ in range(count):
            start = time.time()
            socket.create_connection((target, 80), timeout=SETTINGS["timeout"])
            latency = (time.time() - start) * 1000
            latencies.append(latency)
            print(Fore.GREEN + f"[+] Latency: {latency:.2f} ms" + Style.RESET_ALL)
        avg_latency = sum(latencies) / len(latencies)
        print(Fore.MAGENTA + f"[~] Average Latency: {avg_latency:.2f} ms" + Style.RESET_ALL)
        log_event(f"Network latency test: {target} -> Avg {avg_latency:.2f} ms")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Network latency test failed: {e}", "ERROR")

def protocol_analyzer():
    interface = input(Fore.CYAN + "[>] Interface: " + Style.RESET_ALL)
    try:
        protocols = set()
        def process_packet(packet):
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocols.add(proto)
                print(Fore.GREEN + f"[+] Detected protocol: {proto}" + Style.RESET_ALL)
                log_event(f"Protocol detected: {proto}")
        scapy.sniff(iface=interface, prn=process_packet, count=10)
        print(Fore.MAGENTA + f"[~] Protocols: {protocols}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Protocol analyzer failed: {e}", "ERROR")

def log_file_analyzer():
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        print(Fore.MAGENTA + "[~] Recent log entries (last 10):" + Style.RESET_ALL)
        for line in logs[-10:]:
            print(Fore.GREEN + f"[+] {line.strip()}" + Style.RESET_ALL)
        errors = [log for log in logs if "ERROR" in log]
        print(Fore.RED + f"[!] Errors found: {len(errors)}" + Style.RESET_ALL)
        log_event("Log file analyzed")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Log file analysis failed: {e}", "ERROR")

def ethical_dilemma_analyzer():
    print(Fore.MAGENTA + "[~] Ethical Dilemma Analyzer" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Network action: " + Style.RESET_ALL)
    target = input(Fore.CYAN + "[>] Target (IP/domain): " + Style.RESET_ALL)
    permission = input(Fore.CYAN + "[>] Explicit permission? (yes/no): " + Style.RESET_ALL).lower()
    impact = input(Fore.CYAN + "[>] Potential impact (low/medium/high): " + Style.RESET_ALL).lower()
    result = "Ethical" if permission == "yes" and impact in ["low", "medium"] else "Unethical: Requires permission or high impact"
    print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
    log_event(f"Ethical dilemma analysis: {action} on {target} -> {result}")

def decision_making_framework():
    print(Fore.MAGENTA + "[~] Decision-Making Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    criteria = ["Legality", "Consent", "Impact", "Necessity", "Transparency"]
    scores = {}
    for criterion in criteria:
        score = int(input(Fore.CYAN + f"[>] Score for {criterion} (1-5): " + Style.RESET_ALL))
        scores[criterion] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Proceed" if avg_score >= 3.5 else "Reconsider"
    print(Fore.MAGENTA + "[~] Scores:" + Style.RESET_ALL)
    for k, v in scores.items():
        print(Fore.GREEN + f"[+] {k}: {v}" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Decision: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Decision framework: {action} -> {result}")

def principles_manager():
    print(Fore.MAGENTA + "[~] Ethical Principles Manager" + Style.RESET_ALL)
    principles_file = os.path.join(CONFIG_DIR, "principles.json")
    if not os.path.exists(principles_file):
        with open(principles_file, "w") as f:
            json.dump(["Respect for autonomy", "Non-maleficence", "Beneficence", "Justice"], f, indent=4)
    with open(principles_file, "r") as f:
        principles = json.load(f)
    print(Fore.GREEN + "[+] Current: " + ", ".join(principles) + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Add/Remove (a/r/n): " + Style.RESET_ALL).lower()
    if action == "a":
        new_principle = input(Fore.CYAN + "[>] New principle: " + Style.RESET_ALL)
        principles.append(new_principle)
        print(Fore.GREEN + f"[+] Added: {new_principle}" + Style.RESET_ALL)
        log_event(f"Added principle: {new_principle}")
    elif action == "r":
        principle = input(Fore.CYAN + "[>] Principle to remove: " + Style.RESET_ALL)
        if principle in principles:
            principles.remove(principle)
            print(Fore.GREEN + f"[+] Removed: {principle}" + Style.RESET_ALL)
            log_event(f"Removed principle: {principle}")
    with open(principles_file, "w") as f:
        json.dump(principles, f, indent=4)

def compliance_checker():
    print(Fore.MAGENTA + "[~] Compliance Checker" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    standards = ["GDPR", "HIPAA", "PCI-DSS", "ISO 27001"]
    results = []
    for standard in standards:
        compliant = input(Fore.CYAN + f"[?] Compliant with {standard}? (yes/no): " + Style.RESET_ALL).lower()
        results.append(f"{standard}: {'Compliant' if compliant == 'yes' else 'Non-compliant'}")
    print(Fore.MAGENTA + "[~] Compliance Status:" + Style.RESET_ALL)
    for result in results:
        print(Fore.GREEN + f"[+] {result}" + Style.RESET_ALL)
    log_event(f"Compliance check: {action}; {'; '.join(results)}")

def scenario_generator():
    print(Fore.MAGENTA + "[~] Ethical Scenario Generator" + Style.RESET_ALL)
    scenarios = [
        "Unauthorized port scan on a corporate network",
        "Packet sniffing on public Wi-Fi without consent",
        "Bypassing authentication on a test server",
        "Deploying a honeypot without disclosure",
        "Accessing encrypted data without a warrant"
    ]
    scenario = random.choice(scenarios)
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    analysis = input(Fore.CYAN + "[>] Analyze this scenario? (yes/no): " + Style.RESET_ALL).lower()
    if analysis == "yes":
        permission = input(Fore.CYAN + "[>] Has permission? (yes/no): " + Style.RESET_ALL).lower()
        result = "Ethical" if permission == "yes" else "Unethical: Requires permission"
        print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
        log_event(f"Scenario analysis: {scenario} -> {result}")
    log_event(f"Generated scenario: {scenario}")

def decision_tree_builder():
    print(Fore.MAGENTA + "[~] Decision Tree Builder" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Root Decision: " + Style.RESET_ALL)
    tree = {"action": action, "nodes": []}
    while True:
        node = input(Fore.CYAN + "[>] Add node (condition/outcome, Enter to finish): " + Style.RESET_ALL)
        if not node:
            break
        outcome = input(Fore.CYAN + "[>] Outcome (e.g., Proceed/Stop): " + Style.RESET_ALL)
        tree["nodes"].append({"condition": node, "outcome": outcome})
    print(Fore.MAGENTA + "[~] Decision Tree:" + Style.RESET_ALL)
    print(Fore.GREEN + json.dumps(tree, indent=2) + Style.RESET_ALL)
    with open(os.path.join(CONFIG_DIR, f"tree_{action.replace(' ', '_')}.json"), "w") as f:
        json.dump(tree, f, indent=4)
    log_event(f"Built decision tree: {action}")

def user_signup():
    print(Fore.MAGENTA + "[~] Register New Node" + Style.RESET_ALL)
    username = input(Fore.CYAN + "[>] NETMASK: " + Style.RESET_ALL)
    password = getpass.getpass(Fore.CYAN + "[>] KEYCODE: " + Style.RESET_ALL)
    role = input(Fore.CYAN + "[>] Role (user/admin): " + Style.RESET_ALL).lower()
    role = "user" if role != "admin" else "admin"
    with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
        users_data = json.load(f)
    if any(user['username'] == username for user in users_data['users']):
        print(Fore.RED + "[-] NETMASK exists." + Style.RESET_ALL)
        log_event(f"Sign-up failed: {username} exists", "ERROR")
    else:
        user_id = str(uuid.uuid4())
        otp_secret = pyotp.random_base32()
        users_data['users'].append({
            "id": user_id,
            "username": username,
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "role": role,
            "otp_secret": otp_secret
        })
        with open(os.path.join(CONFIG_DIR, "users.json"), "w") as f:
            json.dump(users_data, f, indent=4)
        print(Fore.GREEN + "[+] Node registered." + Style.RESET_ALL)
        generate_otp_qr({"username": username, "otp_secret": otp_secret})
        log_event(f"User signed up: {username} ({role})")

def automated_backup():
    print(Fore.MAGENTA + "[~] Initiating backup..." + Style.RESET_ALL)
    backup_dir = os.path.join(CONFIG_DIR, "backups")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for file_name in CONFIG_FILES.keys():
        src = os.path.join(CONFIG_DIR, file_name)
        dst = os.path.join(backup_dir, f"{file_name}.{timestamp}.bak")
        try:
            with open(src, "r") as f:
                data = f.read()
            with open(dst, "w") as f:
                f.write(data)
            print(Fore.GREEN + f"[+] Backed up {file_name} to {dst}" + Style.RESET_ALL)
            log_event(f"Backed up: {file_name}")
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
            log_event(f"Backup failed: {e}", "ERROR")

def multi_language_support():
    print(Fore.MAGENTA + "[~] Multi-Language Interface" + Style.RESET_ALL)
    languages = {"en": "English", "es": "Spanish", "fr": "French", "de": "German"}
    print(Fore.GREEN + "[+] Available: " + ", ".join(languages.values()) + Style.RESET_ALL)
    lang = input(Fore.CYAN + "[>] Select language: " + Style.RESET_ALL).lower()
    lang_code = next((code for code, name in languages.items() if name.lower() == lang), "en")
    try:
        translator = Translator(to_lang=lang_code)
        messages = [
            "Network scan completed",
            "Login successful",
            "Report generated"
        ]
        print(Fore.MAGENTA + "[~] Translated messages:" + Style.RESET_ALL)
        for msg in messages:
            translated = translator.translate(msg)
            print(Fore.GREEN + f"[+] {msg} -> {translated}" + Style.RESET_ALL)
        with open(os.path.join(CONFIG_DIR, "settings.json"), "r") as f:
            settings = json.load(f)
        settings["language"] = lang_code
        with open(os.path.join(CONFIG_DIR, "settings.json"), "w") as f:
            json.dump(settings, f, indent=4)
        log_event(f"Language set to: {lang_code}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Multi-language failed: {e}", "ERROR")

def report_generator():
    report_type = input(Fore.CYAN + "[>] Type (summary/detailed): " + Style.RESET_ALL).lower()
    format = input(Fore.CYAN + "[>] Format (txt/csv/pdf): " + Style.RESET_ALL).lower()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(CONFIG_DIR, f"report_{timestamp}.{format}")
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        if format == "txt":
            with open(output_file, "w") as f:
                f.write("HUTNTER Report\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write(f"Type: {report_type}\n\n")
                if report_type == "summary":
                    f.write(f"Total Logs: {len(logs)}\n")
                else:
                    for log in logs:
                        f.write(log)
        elif format == "csv":
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Level", "Message"])
                for log in logs:
                    parts = log.strip().split(" ", 2)
                    writer.writerow([parts[0], parts[1].strip("[]"), parts[2]])
        elif format == "pdf":
            doc = SimpleDocTemplate(output_file, pagesize=letter)
            styles = getSampleStyleSheet()
            story = [
                Paragraph("HUTNTER Report", styles['Title']),
                Paragraph(f"Generated: {datetime.datetime.now()}", styles['Normal']),
                Paragraph(f"Type: {report_type}", styles['Normal']),
                Spacer(1, 12)
            ]
            if report_type == "summary":
                story.append(Paragraph(f"Total Logs: {len(logs)}", styles['Normal']))
            else:
                for log in logs:
                    story.append(Paragraph(log.strip(), styles['Normal']))
            doc.build(story)
        print(Fore.GREEN + f"[+] Report saved: {output_file}" + Style.RESET_ALL)
        log_event(f"Generated {report_type} report: {output_file}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Report generation failed: {e}", "ERROR")

# -------------------- NEW ETHICAL TOOLS --------------------
def risk_assessment():
    print(Fore.MAGENTA + "[~] Risk Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    factors = ["Likelihood", "Impact", "Vulnerability", "Threat Level"]
    scores = {}
    for factor in factors:
        score = int(input(Fore.CYAN + f"[>] {factor} (1-5): " + Style.RESET_ALL))
        scores[factor] = score
    risk_score = sum(scores.values()) / len(factors)
    risk_level = "Low" if risk_score < 2.5 else "Medium" if risk_score < 4 else "High"
    print(Fore.MAGENTA + "[~] Risk Analysis:" + Style.RESET_ALL)
    for k, v in scores.items():
        print(Fore.GREEN + f"[+] {k}: {v}" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Risk Level: {risk_level} (Score: {risk_score:.2f})" + Style.RESET_ALL)
    log_event(f"Risk assessment: {action} -> {risk_level}")

def impact_assessment():
    print(Fore.MAGENTA + "[~] Impact Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    stakeholders = input(Fore.CYAN + "[>] Stakeholders (comma-separated): " + Style.RESET_ALL).split(",")
    impacts = {}
    for stakeholder in stakeholders:
        impact = input(Fore.CYAN + f"[>] Impact on {stakeholder} (low/medium/high): " + Style.RESET_ALL).lower()
        impacts[stakeholder.strip()] = impact
    print(Fore.MAGENTA + "[~] Impact Summary:" + Style.RESET_ALL)
    for k, v in impacts.items():
        print(Fore.GREEN + f"[+] {k}: {v.capitalize()}" + Style.RESET_ALL)
    log_event(f"Impact assessment: {action}")

def case_study_database():
    print(Fore.MAGENTA + "[~] Case Study Database" + Style.RESET_ALL)
    case_file = os.path.join(CONFIG_DIR, "cases.json")
    if not os.path.exists(case_file):
        with open(case_file, "w") as f:
            json.dump([], f)
    with open(case_file, "r") as f:
        cases = json.load(f)
    action = input(Fore.CYAN + "[>] Add/View (a/v): " + Style.RESET_ALL).lower()
    if action == "a":
        case = {
            "id": str(uuid.uuid4()),
            "title": input(Fore.CYAN + "[>] Case title: " + Style.RESET_ALL),
            "description": input(Fore.CYAN + "[>] Description: " + Style.RESET_ALL),
            "outcome": input(Fore.CYAN + "[>] Outcome: " + Style.RESET_ALL)
        }
        cases.append(case)
        with open(case_file, "w") as f:
            json.dump(cases, f, indent=4)
        print(Fore.GREEN + f"[+] Added case: {case['title']}" + Style.RESET_ALL)
        log_event(f"Added case study: {case['title']}")
    elif action == "v":
        print(Fore.MAGENTA + "[~] Cases:" + Style.RESET_ALL)
        for case in cases:
            print(Fore.GREEN + f"[+] {case['id']}: {case['title']} - {case['outcome']}" + Style.RESET_ALL)
        log_event("Viewed case studies")

def analytics_dashboard():
    print(Fore.MAGENTA + "[~] Analytics Dashboard" + Style.RESET_ALL)
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        errors = len([log for log in logs if "ERROR" in log])
        successes = len([log for log in logs if "Success" in log])
        plt.figure(figsize=(8, 6))
        sns.barplot(x=["Errors", "Successes"], y=[errors, successes])
        plt.title("Hutnter Log Analytics")
        plt.savefig(os.path.join(CONFIG_DIR, "analytics.png"))
        plt.close()
        print(Fore.GREEN + f"[+] Analytics saved to {CONFIG_DIR}/analytics.png" + Style.RESET_ALL)
        log_event("Generated analytics dashboard")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Analytics dashboard failed: {e}", "ERROR")

# -------------------- ADMIN TOOLS --------------------
def network_stress_test(user_session):
    if user_session['role'] != "admin":
        print(Fore.RED + "[-] Admin access required." + Style.RESET_ALL)
        log_event(f"Unauthorized stress test attempt: {user_session['username']}", "ERROR")
        return
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    duration = int(input(Fore.CYAN + "[>] Duration (seconds): " + Style.RESET_ALL))
    print(Fore.MAGENTA + "[~] Initiating stress test (mock)..." + Style.RESET_ALL)
    try:
        start = time.time()
        while time.time() - start < duration:
            socket.create_connection((target, 80), timeout=SETTINGS["timeout"])
            print(Fore.GREEN + "[+] Packet sent." + Style.RESET_ALL)
            time.sleep(0.1)
        log_event(f"Stress test completed: {target}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Stress test failed: {e}", "ERROR")

def manage_users(user_session):
    if user_session['role'] != "admin":
        print(Fore.RED + "[-] Admin access required." + Style.RESET_ALL)
        log_event(f"Unauthorized user management attempt: {user_session['username']}", "ERROR")
        return
    print(Fore.MAGENTA + "[~] User Management" + Style.RESET_ALL)
    with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
        users_data = json.load(f)
    print(Fore.GREEN + "[+] Users:" + Style.RESET_ALL)
    for user in users_data['users']:
        print(Fore.GREEN + f"[{user['id']}]: {user['username']} ({user['role']})" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Delete/Reset (d/r/n): " + Style.RESET_ALL).lower()
    if action == "d":
        user_id = input(Fore.CYAN + "[>] User ID to delete: " + Style.RESET_ALL)
        users_data['users'] = [u for u in users_data['users'] if u['id'] != user_id]
        print(Fore.GREEN + "[+] User deleted." + Style.RESET_ALL)
        log_event(f"Deleted user: {user_id}")
    elif action == "r":
        user_id = input(Fore.CYAN + "[>] User ID to reset password: " + Style.RESET_ALL)
        for user in users_data['users']:
            if user['id'] == user_id:
                new_password = getpass.getpass(Fore.CYAN + "[>] New password: " + Style.RESET_ALL)
                user['password'] = hashlib.sha256(new_password.encode()).hexdigest()
                print(Fore.GREEN + "[+] Password reset." + Style.RESET_ALL)
                log_event(f"Reset password for: {user['username']}")
    with open(os.path.join(CONFIG_DIR, "users.json"), "w") as f:
        json.dump(users_data, f, indent=4)

# -------------------- HELP MENU --------------------
def help_menu():
    print(Fore.YELLOW + "\n===== NEON GRID COMMAND INDEX ==================" + Style.RESET_ALL)
    commands = [
        ("1", "Ping Host", "Send ICMP probes with customizable count"),
        ("2", "Port Scanner", "Scan TCP ports with service detection"),
        ("3", "Get IP", "Resolve domain to IP"),
        ("4", "HTTP Headers", "Fetch server headers with status"),
        ("5", "Reverse IP", "Lookup hosted domains"),
        ("6", "DNS Lookup", "Query DNS records"),
        ("7", "Traceroute", "Trace packet route"),
        ("8", "WHOIS", "Fetch domain registration"),
        ("9", "Extended Port Scan", "Scan custom port range"),
        ("10", "Packet Sniffer", "Capture packets with protocol info"),
        ("11", "ARP Spoof Detector", "Detect ARP spoofing"),
        ("12", "MAC Address Lookup", "Find MAC for IP"),
        ("13", "Bandwidth Monitor", "Track network usage"),
        ("14", "SSL Certificate", "Verify SSL details"),
        ("15", "DNS Enumeration", "Enumerate DNS records"),
        ("16", "Network Interfaces", "List adapters with IPs"),
        ("17", "File Integrity", "Compute SHA256 hash"),
        ("18", "Vulnerability Scanner", "Scan for vulnerabilities"),
        ("19", "Packet Injection", "Send test packets (root)"),
        ("20", "Password Strength", "Evaluate password"),
        ("21", "Traffic Analysis", "Analyze network traffic"),
        ("22", "Firewall Rules", "Check rules (mock)"),
        ("23", "OS Fingerprint", "Detect OS"),
        ("24", "Banner Grab", "Fetch service banners"),
        ("25", "Subnet Calculator", "Compute subnet details"),
        ("26", "GeoIP Lookup", "Locate IP geographically"),
        ("27", "HTTP Method Test", "Test HTTP methods"),
        ("28", "DNS Zone Transfer", "Attempt zone transfer"),
        ("29", "Network Latency", "Measure latency"),
        ("30", "Protocol Analyzer", "Analyze protocols"),
        ("31", "Log File Analyzer", "Review logs with error count"),
        ("32", "User Sign-Up", "Register new user with 2FA"),
        ("33", "Ethical Dilemma", "Analyze ethical concerns"),
        ("34", "Decision Framework", "Evaluate actions"),
        ("35", "Principles Manager", "Manage ethical principles"),
        ("36", "Compliance Check", "Verify compliance"),
        ("37", "Scenario Generator", "Create ethical scenarios"),
        ("38", "Decision Tree", "Build decision trees"),
        ("39", "Automated Backup", "Backup config files"),
        ("40", "Multi-Language", "Translate interface"),
        ("41", "Report Generator", "Export reports (txt/pdf/csv)"),
        ("42", "Encrypt File", "Encrypt files with AES"),
        ("43", "Decrypt File", "Decrypt AES-encrypted files"),
        ("44", "SSH Brute-Force", "Test SSH credentials (admin)"),
        ("45", "Email Spoof Test", "Test email spoofing"),
        ("46", "Nmap Scan", "Perform Nmap scan with OS detection"),
        ("47", "FTP Anonymous", "Test FTP anonymous login"),
        ("48", "Network Map", "Map network devices"),
        ("49", "WiFi Passwords", "Retrieve WiFi passwords (Windows)"),
        ("50", "System Info", "Display system details"),
        ("51", "PDF Report", "Generate PDF reports"),
        ("52", "Real-Time Monitor", "Monitor network in real-time"),
        ("53", "Risk Assessment", "Assess action risks"),
        ("54", "Impact Assessment", "Evaluate stakeholder impact"),
        ("55", "Case Study DB", "Manage ethical case studies"),
        ("56", "Analytics Dashboard", "Visualize log metrics"),
        ("57", "Network Stress Test", "Stress test (admin only)"),
        ("58", "Manage Users", "Manage user accounts (admin only)"),
        ("59", "Exit", "Disconnect from CLI")
    ]
    for cmd in commands:
        print(Fore.CYAN + f"{cmd[0]}. {cmd[1]} - {cmd[2]}" + Style.RESET_ALL)
    print(Fore.YELLOW + "\nAdmin Dashboard:")
        print(Fore.CYAN + "- Run `dashboard.py` at http://localhost:8080")
        print(Fore.CYAN + "- Features: User management, DDoS whitelist, metrics, admin tools")
        print(Fore.CYAN + "- Default: NETMASK@Ethan, KEYCODE@Admin")
        print(Fore.CYAN + "\nCommands: s (search), h (help)")
    log_event("Displayed help menu")

def search_menu():
    query = input(Fore.CYAN + "[>] Search tool: " + Style.RESET_ALL).lower()
    commands = [
        ("1", "Ping Host", "Send ICMP probes"),
        ("2", "Port Scanner", "Scan TCP ports"),
        ("3", "Get IP", "Resolve domain"),
        ("4", "HTTP Headers", "Fetch headers"),
        ("5", "Reverse IP", "Lookup domains"),
        ("6", "DNS Lookup", "Query DNS"),
        ("7", "Traceroute", "Trace route"),
        ("8", "WHOIS", "Domain registration"),
        ("9", "Extended Port Scan", "Custom ports"),
        ("10", "Packet Sniffer", "Capture packets"),
        ("11", "ARP Spoof Detector", "Detect spoofing"),
        ("12", "MAC Address Lookup", "Find MAC"),
        ("13", "Bandwidth Monitor", "Track usage"),
        ("14", "SSL Certificate", "Verify SSL"),
        ("15", "DNS Enumeration", "Enumerate records"),
        ("16", "Network Interfaces", "List adapters"),
        ("17", "File Integrity", "SHA256 hash"),
        ("18", "Vulnerability Scanner", "Scan vulns"),
        ("19", "Packet Injection", "Send packets"),
        ("20", "Password Strength", "Evaluate password"),
        ("21", "Traffic Analysis", "Analyze traffic"),
        ("22", "Firewall Rules", "Check rules"),
        ("23", "OS Fingerprint", "Detect OS"),
        ("24", "Banner Grab", "Fetch banners"),
        ("25", "Subnet Calculator", "Compute subnets"),
        ("26", "GeoIP Lookup", "Locate IP"),
        ("27", "HTTP Method Test", "Test methods"),
        ("28", "DNS Zone Transfer", "Test transfer"),
        ("29", "Network Latency", "Measure latency"),
        ("30", "Protocol Analysis", "Analyze protocols"),
        ("31", "Log File Analyzer", "Review logs"),
        ("32", "User Sign-Up", "Register user"),
        ("33", "Ethical Dilemma", "Analyze ethics"),
        ("34", "Decision Framework", "Evaluate actions"),
        ("35", "Principles Manager", "Manage principles"),
        ("36", "Compliance Check", "Verify compliance"),
        ("37", "Scenario Generator", "Create scenarios"),
        ("38", "Decision Tree", "Build trees"),
        ("39", "Automated Backup", "Backup configs"),
        ("40", "Multi-Language", "Translate interface"),
        ("41", "Report Generator", "Export reports"),
        ("42", "Encrypt File", "AES encryption"),
        ("43", "Decrypt File", "AES decryption"),
        ("44", "SSH Brute Force", "Test SSH"),
        ("45", "Email Spoof Test",
