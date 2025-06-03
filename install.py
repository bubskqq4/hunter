import subprocess
import sys
import importlib.util

# Only external packages (standard libs like os, sys, re, etc. don't need installing)
required_packages = [
    "colorama",     # for terminal colors
    "requests",     # for HTTP requests
    "dnspython",    # provides dns.resolver
    "psutil",       # system info (CPU, RAM, etc.)
    "netifaces"     # for network interface info
]

def is_installed(package):
    return importlib.util.find_spec(package) is not None

def install(package):
    if is_installed(package):
        print(f"[✓] {package} is already installed.")
    else:
        try:
            print(f"[+] Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except Exception as e:
            print(f"[!] Failed to install {package}: {e}")

def main():
    print("[*] Installing dependencies needed for hunter.py...\n")
    for package in required_packages:
        install(package)
    print("\n[✓] All dependencies processed.")

if __name__ == "__main__":
    main()
