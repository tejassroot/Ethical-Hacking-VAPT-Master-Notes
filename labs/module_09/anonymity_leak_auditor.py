#!/usr/bin/env python3
"""
================================================================================
MODULE 09 LAB: ANONYMITY POSTURE & TRANSPORT LEAK AUDITOR
PURPOSE: Programmatic verification of DNS leaks, proxy routing, and exit node status.
COMPLIANCE: Authorized diagnostic auditing / Non-destructive privacy verification.
================================================================================
"""

import urllib.request
import urllib.error
import json
import socket
import sys

def audit_egress_ip():
    print("=" * 72)
    print("[*] STEP 1: AUDITING PUBLIC EGRESS IP & TOR EXIT STATUS")
    print("=" * 72)
    
    headers = {"User-Agent": "AnonymityAuditor/1.0"}
    req = urllib.request.Request("https://check.torproject.org/api/ip", headers=headers)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                ip = data.get("IP", "Unknown")
                is_tor = data.get("IsTor", False)
                print(f"[+] Current Public Egress IP: {ip}")
                print(f"[+] Tor Network Exit Node Status: {'YES (ANONYMOUS)' if is_tor else 'NO (DIRECT/NON-TOR)'}")
                return ip, is_tor
    except Exception as e:
        print(f"[*] Egress check note: {e}")
        return "127.0.0.1", False

def audit_local_dns_configuration():
    print("\n" + "=" * 72)
    print("[*] STEP 2: AUDITING SYSTEM RESOLVER LEAK SURFACE")
    print("=" * 72)
    
    nameservers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
    except FileNotFoundError:
        nameservers = ["127.0.0.53"]

    print(f"[+] Configured System DNS Nameservers: {', '.join(nameservers)}")
    
    has_loopback = any(ns.startswith("127.") or ns == "::1" for ns in nameservers)
    if has_loopback:
        print("[+] PASS: System utilizes local loopback resolver (e.g. systemd-resolved/Tor/DNSCrypt).")
    else:
        print("[!] NOTICE: System DNS points directly to external WAN IP (Potential DNS Leak Surface).")

def audit_ipv6_privacy_extensions():
    print("\n" + "=" * 72)
    print("[*] STEP 3: AUDITING IPV6 HARDWARE MAC PRIVACY EXTENSIONS")
    print("=" * 72)
    
    try:
        with open("/proc/sys/net/ipv6/conf/all/use_tempaddr", "r") as f:
            val = int(f.read().strip())
            if val == 2:
                print("[+] [SECURE] IPv6 Privacy Extensions ENFORCED (use_tempaddr = 2).")
                print("    Temporary randomized IPv6 addresses used; MAC address is shielded.")
            else:
                print(f"[!] [INSECURE] IPv6 Privacy Extensions disabled or weak (val = {val}).")
                print("    Risk: Global IPv6 address may embed physical NIC MAC via EUI-64.")
    except FileNotFoundError:
        print("[*] IPv6 is disabled at the kernel level (No IPv6 leak surface).")

if __name__ == "__main__":
    audit_egress_ip()
    audit_local_dns_configuration()
    audit_ipv6_privacy_extensions()
    print("\n[+] ANONYMITY & LEAK AUDIT COMPLETE.")
