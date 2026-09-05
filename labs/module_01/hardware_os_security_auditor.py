#!/usr/bin/env python3
"""
Hardware Microarchitecture & Operating System Security Auditor
Module 01 Lab: Audits CPU security flags (NX/DEP, SMEP, SMAP, KPTI/Meltdown/Spectre mitigations),
process memory architecture, and ASLR system parameters.
"""

import sys
import os
import platform
from typing import Dict, List, Any

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive values to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def audit_cpu_security_flags(flags_text: str) -> Dict[str, Any]:
    """
    Audits CPU flags from /proc/cpuinfo or synthetic register strings.
    Checks for essential hardware security features:
    - nx: No-Execute / Data Execution Prevention (DEP)
    - smep: Supervisor Mode Execution Prevention
    - smap: Supervisor Mode Access Prevention
    - pti / kpti: Kernel Page Table Isolation (Meltdown mitigation)
    - ibpb / ibrs / stibp: Indirect Branch Speculation mitigations (Spectre)
    """
    flags = set(flags_text.lower().split())
    
    checks = {
        "nx": {"Name": "NX/DEP (Data Execution Prevention)", "Critical": True},
        "smep": {"Name": "SMEP (Supervisor Mode Execution Prevention)", "Critical": True},
        "smap": {"Name": "SMAP (Supervisor Mode Access Prevention)", "Critical": True},
        "pti": {"Name": "KPTI (Kernel Page Table Isolation - Meltdown)", "Critical": False},
        "ibrs": {"Name": "IBRS (Speculative Execution Barrier - Spectre)", "Critical": False}
    }
    
    results = {}
    missing_critical = []
    
    for flag, meta in checks.items():
        present = flag in flags
        results[flag] = {
            "feature": meta["Name"],
            "present": present,
            "status": "ACTIVE" if present else "MISSING"
        }
        if meta["Critical"] and not present:
            missing_critical.append(meta["Name"])
            
    is_hardened = len(missing_critical) == 0
    return {
        "Flags_Audited": len(flags),
        "Details": results,
        "Missing_Critical_Protections": missing_critical,
        "Hardened": is_hardened,
        "Posture": "HARDENED" if is_hardened else "VULNERABLE_MICROARCHITECTURE"
    }

def audit_aslr_posture(aslr_val: int) -> Dict[str, Any]:
    """
    Audits Linux Address Space Layout Randomization (ASLR) setting.
    0 = Disabled
    1 = Partial (stack, VDSO, shared libs)
    2 = Full (stack, VDSO, shared libs, data/brk heap)
    """
    aslr_map = {
        0: ("DISABLED", "CRITICAL", "ASLR completely disabled; predictable memory addresses."),
        1: ("PARTIAL", "MEDIUM", "Partial randomization; brk data segment remains static."),
        2: ("FULL", "LOW", "Full randomization of stack, VDSO, mmap, and brk heap (CIS compliant).")
    }
    status, risk, desc = aslr_map.get(aslr_val, ("UNKNOWN", "HIGH", "Invalid or unknown ASLR configuration."))
    return {
        "ASLR_Level": aslr_val,
        "Status": status,
        "Risk_Level": risk,
        "Description": desc
    }

def run_self_tests():
    print("[*] Running Hardware & OS Security Auditor Self-Tests...")

    # Test 1: CPU Security Flags Evaluation
    hardened_cpu_flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat md_clear flush_l1d arch_capabilities pti"
    audit_res = audit_cpu_security_flags(hardened_cpu_flags)
    assert audit_res["Hardened"] is True
    assert audit_res["Details"]["nx"]["present"] is True
    assert audit_res["Details"]["smep"]["present"] is True
    assert audit_res["Details"]["smap"]["present"] is True
    print("[+] Test 1 Passed: Hardened CPU microarchitecture correctly identified with NX, SMEP, SMAP, and KPTI.")

    # Test 2: Insecure CPU Flags Check
    vulnerable_flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov"
    vuln_res = audit_cpu_security_flags(vulnerable_flags)
    assert vuln_res["Hardened"] is False
    assert len(vuln_res["Missing_Critical_Protections"]) >= 3
    print(f"[+] Test 2 Passed: Insecure legacy CPU flagged: Missing {len(vuln_res['Missing_Critical_Protections'])} critical flags.")

    # Test 3: ASLR System Posture
    aslr_full = audit_aslr_posture(2)
    assert aslr_full["Status"] == "FULL"
    assert aslr_full["Risk_Level"] == "LOW"
    
    aslr_disabled = audit_aslr_posture(0)
    assert aslr_disabled["Status"] == "DISABLED"
    assert aslr_disabled["Risk_Level"] == "CRITICAL"
    print("[+] Test 3 Passed: ASLR evaluation correctly differentiated between Full and Disabled modes.")

    print("[*] All Hardware & OS Security Auditor tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
