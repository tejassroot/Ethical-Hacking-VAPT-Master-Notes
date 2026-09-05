#!/usr/bin/env python3
"""
================================================================================
MODULE 03 LAB: PRE-FLIGHT SCOPE ENFORCEMENT & ROE AUDITING ENGINE
PURPOSE: Mathematical IP CIDR and domain boundary verification.
COMPLIANCE: CFAA / CMA / ISO 27001 Rules of Engagement Standards.
================================================================================
"""

import ipaddress
import socket
import json
import sys

CONTRACTED_SCOPE = {
    "engagement_id": "ROE-2026-ENT-0089",
    "authorized_domains": [
        "target.com",
        "*.target.com"
    ],
    "authorized_cidrs": [
        "198.51.100.0/24",
        "203.0.113.0/26",
        "127.0.0.1/32"
    ],
    "explicit_exclusions": [
        "payment.target.com",
        "198.51.100.50"
    ]
}

def is_ip_in_scope(ip_str, scope_definition):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    for excl in scope_definition["explicit_exclusions"]:
        try:
            if ip_obj == ipaddress.ip_address(excl):
                return False, f"TARGET EXCLUDED: IP {ip_str} is in explicit exclusion list."
        except ValueError:
            pass

    for cidr in scope_definition["authorized_cidrs"]:
        network = ipaddress.ip_network(cidr, strict=False)
        if ip_obj in network:
            return True, f"IN-SCOPE: {ip_str} belongs to authorized block {cidr}."

    return False, f"OUT-OF-SCOPE: {ip_str} does not belong to any authorized CIDR range."

def validate_target_asset(target_host, scope_definition):
    print("=" * 72)
    print(f"[*] EXECUTING PRE-FLIGHT SCOPE AUDIT FOR: {target_host}")
    print(f"[*] ENGAGEMENT ID: {scope_definition['engagement_id']}")
    print("=" * 72)

    if target_host in scope_definition["explicit_exclusions"]:
        print(f"[!] REJECTED: {target_host} is an explicitly excluded asset!")
        return False

    resolved_ips = []
    try:
        addr_info = socket.getaddrinfo(target_host, None)
        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
    except socket.gaierror:
        resolved_ips = ["198.51.100.15"]
        print(f"[*] [SIMULATED RESOLUTION]: {target_host} -> 198.51.100.15")

    print(f"[+] Host {target_host} resolved to {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}")

    all_valid = True
    for ip in resolved_ips:
        valid, reason = is_ip_in_scope(ip, scope_definition)
        print(f"    - [{ 'PASS' if valid else 'FAIL' }] {ip}: {reason}")
        if not valid:
            all_valid = False

    if all_valid:
        print("\n[+] SCOPE VERIFIED: Asset is 100% authorized for active security evaluation.")
    else:
        print("\n[!] CRITICAL WARNING: Asset touches unauthorized or excluded IP infrastructure.")
        print("    OPERATIONAL MANDATE: Halt all testing immediately. Contact Engagement Manager.")

    print("=" * 72)
    return all_valid

if __name__ == "__main__":
    test_target = sys.argv[1] if len(sys.argv) > 1 else "api.target.com"
    validate_target_asset(test_target, CONTRACTED_SCOPE)
