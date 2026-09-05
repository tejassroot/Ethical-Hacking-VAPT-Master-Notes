#!/usr/bin/env python3
"""
Module 04 Lab: Virtual Lab Topology & Container Security Checker
Author: Tejas's Ethical Hacking & VAPT Curriculum
Architecture: Standalone Python 3 (Zero external pip dependencies)

Description:
Provides automated verification for ethical hacking & VAPT staging labs:
1. Virtual Lab Topology Auditor: Validates host-only vs bridged configurations, RFC 1918 compliance,
   and prevents accidental WAN exposure.
2. Container Isolation Auditor: Analyzes Docker/container configurations for privilege escalation
   risks (e.g., privileged mode, docker.sock mount, host networking, dangerous Linux capabilities).
"""

import sys
import ipaddress
from typing import Dict, List, Any, Optional

# --- SECTION 1: VIRTUAL LAB TOPOLOGY AUDITOR ---

class VirtualLabTopologyAuditor:
    """
    Validates virtual network adapters, subnet segregation, and routing boundaries
    to guarantee safe, isolated pentesting environments.
    """

    ALLOWED_PENTEST_SUBNETS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8")
    ]

    @classmethod
    def audit_interface(cls, name: str, ip_str: str, netmask_str: str, mode: str) -> Dict[str, Any]:
        """
        Audits an individual network adapter interface.
        Modes: 'HOST_ONLY', 'INTERNAL', 'NAT', 'BRIDGED'
        """
        issues = []
        try:
            interface_ip = ipaddress.ip_interface(f"{ip_str}/{netmask_str}")
            network = interface_ip.network
        except ValueError as e:
            return {
                "interface": name,
                "status": "ERROR",
                "issues": [f"Invalid IP/Netmask specification: {str(e)}"]
            }

        # Check 1: RFC 1918 Private Addressing Compliance
        is_private = any(network.subnet_of(parent) for parent in cls.ALLOWED_PENTEST_SUBNETS)
        if not is_private:
            issues.append(f"CRITICAL: Interface bound to public/non-RFC1918 IP ({ip_str}). Potential WAN leak!")

        # Check 2: Bridged Mode Warning
        if mode.upper() == "BRIDGED":
            issues.append("WARNING: Bridged adapter detected. Host/VM is directly reachable from local physical LAN.")

        # Check 3: Check for broadcast address leakage risk
        if interface_ip.ip == network.network_address or interface_ip.ip == network.broadcast_address:
            issues.append("ERROR: Interface assigned to reserved network or broadcast address.")

        status = "COMPLIANT" if not issues else ("HIGH_RISK" if any("CRITICAL" in i for i in issues) else "WARNING")

        return {
            "interface": name,
            "ip": ip_str,
            "network": str(network),
            "mode": mode.upper(),
            "status": status,
            "issues": issues
        }

    @classmethod
    def audit_dual_homed_pivot(cls, iface1: Dict[str, Any], iface2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates dual-NIC pivot configuration between an External/DMZ subnet and an Internal LAN.
        """
        net1 = ipaddress.ip_network(iface1["network"])
        net2 = ipaddress.ip_network(iface2["network"])

        overlap = net1.overlaps(net2)
        valid_pivot = not overlap and iface1["mode"] in ("NAT", "HOST_ONLY") and iface2["mode"] in ("HOST_ONLY", "INTERNAL")

        return {
            "is_valid_pivot_host": valid_pivot,
            "network_overlap": overlap,
            "dmz_network": str(net1),
            "internal_network": str(net2),
            "remedy": "Separate subnets and disable auto-promiscuous mode to ensure deterministic routing."
        }


# --- SECTION 2: CONTAINER ISOLATION AUDITOR ---

DANGEROUS_CAPABILITIES = {
    "CAP_SYS_ADMIN": "Enables root-equivalent kernel operations, mount manipulation, and potential container escape.",
    "CAP_NET_ADMIN": "Allows routing table modifications, interface promiscuous mode, and ARP spoofing from container.",
    "CAP_SYS_PTRACE": "Allows debugging and inspecting memory of host/container processes.",
    "CAP_DAC_OVERRIDE": "Bypasses standard file read/write/execute permission checks."
}

DANGEROUS_MOUNTS = [
    "/var/run/docker.sock",
    "/proc/sys",
    "/sys",
    "/",
    "/etc"
]

class ContainerIsolationAuditor:
    """
    Evaluates Docker / container configurations for escape vectors,
    over-privileged flags, and shared host namespaces.
    """

    @classmethod
    def audit_config(cls, container_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = []

        # 1. Privileged flag check
        if config.get("privileged", False) is True:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "vector": "Privileged Container Mode",
                "description": "Container executes with full host root capabilities, granting raw device access."
            })

        # 2. Host namespace sharing
        if config.get("network_mode", "").lower() == "host":
            vulnerabilities.append({
                "severity": "HIGH",
                "vector": "Host Network Namespace Sharing",
                "description": "Container shares network stack with host; bypasses firewall isolation."
            })

        if config.get("pid_mode", "").lower() == "host":
            vulnerabilities.append({
                "severity": "HIGH",
                "vector": "Host PID Namespace Sharing",
                "description": "Container can view and signal all processes running on the host OS."
            })

        # 3. Dangerous socket / filesystem mounts
        mounts = config.get("volumes", [])
        for m in mounts:
            host_path = m.split(":")[0] if ":" in m else m
            if any(host_path.startswith(bad_mount) for bad_mount in DANGEROUS_MOUNTS):
                vulnerabilities.append({
                    "severity": "CRITICAL",
                    "vector": f"Sensitive Host Mount ({host_path})",
                    "description": "Mounting host sockets or root filesystems facilitates trivial host breakout."
                })

        # 4. Dangerous capabilities added
        added_caps = config.get("cap_add", [])
        for cap in added_caps:
            cap_upper = cap.upper()
            if cap_upper in DANGEROUS_CAPABILITIES:
                vulnerabilities.append({
                    "severity": "HIGH",
                    "vector": f"Excessive Linux Capability ({cap_upper})",
                    "description": DANGEROUS_CAPABILITIES[cap_upper]
                })

        # Overall posture
        posture = "SECURE" if not vulnerabilities else ("COMPROMISED_POSTURE" if any(v["severity"] == "CRITICAL" for v in vulnerabilities) else "NEEDS_HARDENING")

        return {
            "container_id": container_id,
            "posture": posture,
            "total_vulnerabilities": len(vulnerabilities),
            "findings": vulnerabilities,
            "recommended_hardening": [
                "Set read_only: true for root filesystem",
                "Drop all capabilities by default (cap_drop: ['ALL']) and selectively add only necessary ones",
                "Avoid mounting /var/run/docker.sock into untrusted workloads"
            ]
        }


# --- SECTION 3: DETERMINISTIC SELF-TEST SUITE ---

def run_self_tests() -> bool:
    print("[*] Running Virtual Lab Topology & Container Security Self-Tests...")

    # Test 1: Isolated Host-Only Network Adapter
    host_only = VirtualLabTopologyAuditor.audit_interface(
        name="vboxnet0",
        ip_str="192.168.56.10",
        netmask_str="255.255.255.0",
        mode="HOST_ONLY"
    )
    assert host_only["status"] == "COMPLIANT", f"Expected COMPLIANT, got {host_only['status']}"
    assert len(host_only["issues"]) == 0
    print(f"[+] Test 1 Passed: Isolated Host-Only adapter {host_only['interface']} verified compliant.")

    # Test 2: Insecure Bridged Interface with Public Leak
    insecure_iface = VirtualLabTopologyAuditor.audit_interface(
        name="eth0",
        ip_str="203.0.113.5",
        netmask_str="255.255.255.0",
        mode="BRIDGED"
    )
    assert insecure_iface["status"] == "HIGH_RISK", f"Expected HIGH_RISK, got {insecure_iface['status']}"
    assert len(insecure_iface["issues"]) >= 2
    print(f"[+] Test 2 Passed: Public bridged interface flagged with {len(insecure_iface['issues'])} security issues.")

    # Test 3: Dual-Homed Pivot Audit
    pivot_res = VirtualLabTopologyAuditor.audit_dual_homed_pivot(
        iface1={"network": "192.168.56.0/24", "mode": "HOST_ONLY"},
        iface2={"network": "10.10.10.0/24", "mode": "INTERNAL"}
    )
    assert pivot_res["is_valid_pivot_host"] is True
    assert pivot_res["network_overlap"] is False
    print("[+] Test 3 Passed: Multi-NIC pivot segregation successfully validated.")

    # Test 4: Container Isolation - Privileged & Docker Socket Mount
    risky_container = {
        "privileged": True,
        "network_mode": "host",
        "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
        "cap_add": ["CAP_SYS_ADMIN"]
    }
    c_audit = ContainerIsolationAuditor.audit_config("vuln-target-staging", risky_container)
    assert c_audit["posture"] == "COMPROMISED_POSTURE"
    assert c_audit["total_vulnerabilities"] == 4, f"Expected 4 vulnerabilities, got {c_audit['total_vulnerabilities']}"
    print(f"[+] Test 4 Passed: Highly permissive container correctly flagged with {c_audit['total_vulnerabilities']} escape vectors.")

    print("[*] All Virtual Lab Topology & Container Security tests completed with 100% success.")
    return True


if __name__ == "__main__":
    if len(sys.argv) == 1:
        success = run_self_tests()
        sys.exit(0 if success else 1)
    else:
        print("Usage: python3 virtual_lab_topology_checker.py (Runs self-tests by default)")
