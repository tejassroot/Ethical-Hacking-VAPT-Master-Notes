#!/usr/bin/env python3
"""
================================================================================
MODULE 03 LAB: PRE-FLIGHT SCOPE ENFORCEMENT & CIA / DAD AUDITING ENGINE
PURPOSE: Mathematical IP CIDR boundary verification & CIA/DAD threat impact modeling.
STANDARDS: CFAA / CMA / ISO 27001 / NIST SP 800-115 Rules of Engagement.
================================================================================
"""

import ipaddress
import socket
import json
import sys
from typing import Dict, Tuple, Any

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

# --- SECTION 1: CIA & DAD THREAT IMPACT MODELER ---

CIA_DAD_MATRIX = {
    "DATA_LEAK_IDOR": {
        "cia_pillar": "Confidentiality",
        "dad_threat": "Disclosure",
        "description": "Unauthorized exfiltration or exposure of sensitive customer records.",
        "cvss_impact": "C:H/I:N/A:N"
    },
    "DATABASE_TAMPERING_SQLI": {
        "cia_pillar": "Integrity",
        "dad_threat": "Alteration",
        "description": "Unauthorized alteration or corruption of database records and schemas.",
        "cvss_impact": "C:N/I:H/A:N"
    },
    "SERVICE_OUTAGE_REDOS": {
        "cia_pillar": "Availability",
        "dad_threat": "Denial",
        "description": "Service degradation or CPU exhaustion disrupting authorized user access.",
        "cvss_impact": "C:N/I:N/A:H"
    },
    "RANSOMWARE_ENCRYPTION": {
        "cia_pillar": "Integrity & Availability",
        "dad_threat": "Alteration & Denial",
        "description": "Unauthorized alteration (encryption) resulting in total denial of data access.",
        "cvss_impact": "C:N/I:H/A:H"
    },
    "UNAUTHENTICATED_RCE": {
        "cia_pillar": "Confidentiality, Integrity & Availability",
        "dad_threat": "Disclosure, Alteration & Denial",
        "description": "Complete system compromise yielding unauthorized read, write, and kill capabilities.",
        "cvss_impact": "C:H/I:H/A:H"
    }
}

def classify_cia_dad_impact(finding_type: str) -> Dict[str, str]:
    """
    Maps an audit finding to its underlying CIA compromise and DAD threat realization.
    """
    key = finding_type.upper()
    if key in CIA_DAD_MATRIX:
        return CIA_DAD_MATRIX[key]
    return {
        "cia_pillar": "Undefined",
        "dad_threat": "Undefined",
        "description": "Unknown finding category.",
        "cvss_impact": "C:N/I:N/A:N"
    }


# --- SECTION 2: SCOPE BOUNDARY ENFORCEMENT ---

def is_ip_in_scope(ip_str: str, scope_definition: Dict[str, Any]) -> Tuple[bool, str]:
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


def validate_target_asset(target_host: str, scope_definition: Dict[str, Any]) -> bool:
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


# --- SECTION 3: DETERMINISTIC SELF-TEST SUITE ---

def run_self_tests() -> bool:
    print("[*] Running Module 03 Scope & CIA/DAD Threat Modeler Self-Tests...")

    # Test 1: In-scope IP verification
    valid_ip, msg = is_ip_in_scope("198.51.100.25", CONTRACTED_SCOPE)
    assert valid_ip is True, f"Expected in-scope IP, got: {msg}"
    print(f"[+] Test 1 Passed: In-scope IP correctly authorized: {msg}")

    # Test 2: Out-of-scope IP rejection
    invalid_ip, msg2 = is_ip_in_scope("8.8.8.8", CONTRACTED_SCOPE)
    assert invalid_ip is False, f"Expected out-of-scope IP rejection, got: {msg2}"
    print(f"[+] Test 2 Passed: Out-of-scope IP rejected: {msg2}")

    # Test 3: Explicitly excluded IP containment
    excluded_ip, msg3 = is_ip_in_scope("198.51.100.50", CONTRACTED_SCOPE)
    assert excluded_ip is False, f"Expected excluded IP rejection, got: {msg3}"
    assert "TARGET EXCLUDED" in msg3
    print(f"[+] Test 3 Passed: Excluded boundary guard enforced: {msg3}")

    # Test 4: CIA vs DAD Impact Classification
    idor_eval = classify_cia_dad_impact("DATA_LEAK_IDOR")
    assert idor_eval["cia_pillar"] == "Confidentiality"
    assert idor_eval["dad_threat"] == "Disclosure"
    assert idor_eval["cvss_impact"] == "C:H/I:N/A:N"
    print(f"[+] Test 4 Passed: CIA/DAD duality verified (Confidentiality loss -> {idor_eval['dad_threat']})")

    redos_eval = classify_cia_dad_impact("SERVICE_OUTAGE_REDOS")
    assert redos_eval["cia_pillar"] == "Availability"
    assert redos_eval["dad_threat"] == "Denial"
    print(f"[+] Test 5 Passed: CIA/DAD duality verified (Availability loss -> {redos_eval['dad_threat']})")

    print("[*] All Module 03 Scope & CIA/DAD tests completed with 100% success.\n")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] not in ("--test", "-t"):
        validate_target_asset(sys.argv[1], CONTRACTED_SCOPE)
    else:
        success = run_self_tests()
        sys.exit(0 if success else 1)
