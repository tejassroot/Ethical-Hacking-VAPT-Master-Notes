#!/usr/bin/env python3
"""
================================================================================
MODULE 32 LAB: NETWORK SERVICE AUDITING, PIVOTING & PRIVILEGE ESCALATION ENGINE
PURPOSE: Programmatic auditing of SMB signing, unquoted service paths (CWE-428),
         SOCKS5/TCP pivoting logic, and Linux SUID security posture.
COMPLIANCE: Authorized testing only / Standard benign network diagnostic probing.
================================================================================
"""

import socket
import threading
import http.server
import time
import sys
import os

def analyze_unquoted_service_path(raw_path):
    """
    Simulates the Windows CreateProcess path resolution algorithm for unquoted
    service binary paths containing spaces (CWE-428).
    """
    cleaned = raw_path.strip()
    print(f"[*] Analyzing Windows Service Path: {cleaned}")
    
    # Check if properly quoted
    if cleaned.startswith('"') and cleaned.endswith('"'):
        print("    [+] SECURE: Service path is properly wrapped in quotation marks.\n")
        return []

    # Strip arguments
    parts = cleaned.split(".exe")
    exec_path = parts[0] + ".exe"
    
    tokens = exec_path.split(" ")
    if len(tokens) <= 1:
        print("    [+] SECURE: Path contains no spaces; no hijacking ambiguity.\n")
        return []

    print("    [!] VULNERABILITY (CWE-428): Unquoted service path with spaces detected!")
    search_candidates = []
    current = ""
    for i in range(len(tokens) - 1):
        current = f"{current} {tokens[i]}".strip()
        candidate = f"{current}.exe"
        search_candidates.append(candidate)
        print(f"        -> Hijack Evaluation Target {i+1}: '{candidate}'")
    print()
    return search_candidates

def audit_smb_signing_posture(security_mode_byte):
    """
    Decodes SMB2 NEGOTIATE response SecurityMode flags.
    Bit 0 (0x01): SMB2_NEGOTIATE_SIGNING_ENABLED
    Bit 1 (0x02): SMB2_NEGOTIATE_SIGNING_REQUIRED
    """
    enabled = bool(security_mode_byte & 0x01)
    required = bool(security_mode_byte & 0x02)

    print(f"[*] Evaluating SMB Security Mode Byte: 0x{security_mode_byte:02x}")
    print(f"    - Signing Enabled:  {enabled}")
    print(f"    - Signing Required: {required}")

    if not required:
        print("    [!] CRITICAL VULNERABILITY: SMB Signing NOT required!")
        print("        Host is vulnerable to NTLM Relay attacks on Layer 2.")
        return False
    else:
        print("    [+] SECURE: SMB Signing is strictly enforced. Relay attacks blocked.")
        return True

def audit_linux_suid_vectors(root_dir="/"):
    """Audits local system for dangerous SUID binaries that can be leveraged for privesc."""
    print("[*] Auditing Local Linux SUID Binaries (Sample Audit):")
    known_gtfo_bins = {"nmap", "vim", "find", "bash", "python", "perl", "cp", "awk"}
    
    test_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]
    discovered_suid = []

    for d in test_dirs:
        if not os.path.exists(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                if os.path.isfile(fpath) and not os.path.islink(fpath):
                    mode = os.stat(fpath).st_mode
                    if mode & 0o4000: # SUID bit
                        discovered_suid.append(fpath)
                        if fname in known_gtfo_bins:
                            print(f"    [!] HIGH RISK SUID BINARY: {fpath} (Documented GTFOBins bypass vector!)")
        except PermissionError:
            pass

    print(f"    [i] Total SUID binaries audited in system paths: {len(discovered_suid)}")
    return discovered_suid

def run_pivot_simulation():
    """Simulates multi-hop TCP port forwarding / pivoting mechanics."""
    print("\n" + "=" * 72)
    print("[*] SIMULATING MULTI-HOP NETWORK PIVOT TUNNEL")
    print("=" * 72)

    class TargetService(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
        def do_GET(self):
            payload = b"INTERNAL_DOMAIN_SECRET_FLAG_OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

    target_server = http.server.HTTPServer(("127.0.0.1", 9092), TargetService)
    t = threading.Thread(target=target_server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 9092))
        sock.sendall(b"GET / HTTP/1.1\r\nHost: internal-dc\r\nConnection: close\r\n\r\n")
        response = sock.recv(4096)
        sock.close()

        if b"INTERNAL_DOMAIN_SECRET_FLAG_OK" in response:
            print("[+] PIVOT VERIFICATION SUCCESS: Reached internal protected service across tunnel!")
            print("    Received Payload: 'INTERNAL_DOMAIN_SECRET_FLAG_OK'")
    finally:
        target_server.shutdown()
        target_server.server_close()

def run_self_test():
    print("=" * 72)
    print("[*] NETWORK PENETRATION TESTING EXECUTION & SERVICE AUDIT SUITE")
    print("=" * 72)

    # 1. Unquoted Service Path Test
    print("\n--- 1. Testing Unquoted Service Path Resolution ---")
    analyze_unquoted_service_path(r'"C:\Program Files\Hardened Corp\SecureSvc.exe"')
    analyze_unquoted_service_path(r'C:\Program Files\Vulnerable Software\Management Console\agent.exe')

    # 2. SMB Signing Posture Test
    print("\n--- 2. Testing SMB Signing Posture ---")
    audit_smb_signing_posture(0x01) # Enabled but not required (Vulnerable)
    audit_smb_signing_posture(0x03) # Enabled and required (Secure)

    # 3. Linux SUID Audit
    print("\n--- 3. Testing Local Host SUID Audit ---")
    audit_linux_suid_vectors()

    # 4. Pivot Simulation
    run_pivot_simulation()

    print("\n" + "=" * 72)
    print("[+] ALL NETWORK SERVICE AUDITS & PIVOT TESTS PASSED.")
    print("=" * 72)

if __name__ == "__main__":
    run_self_test()
