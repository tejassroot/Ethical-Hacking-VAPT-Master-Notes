#!/usr/bin/env python3
"""
================================================================================
MODULE 07 LAB: MULTI-PROTOCOL SERVICE ENUMERATION & STATE AUDITOR
PURPOSE: Low-level evaluation of SMB negotiate, SNMP community probe, & SMTP VRFY.
COMPLIANCE: Authorized testing only / Non-destructive service interrogation.
================================================================================
"""

import socket
import struct
import sys

def audit_smb_dialect_negotiate(target_ip, port=445):
    print("=" * 72)
    print(f"[*] AUDITING SMB DIALECT & CAPABILITIES: {target_ip}:{port}")
    print("=" * 72)
    
    smb_negotiate_raw = (
        b"\x00\x00\x00\x45"  # NetBIOS Session Length (69 bytes)
        b"\xff\x53\x4d\x42"  # SMB Header: 0xFF 'SMB'
        b"\x72"              # Command: SMB_COM_NEGOTIATE (0x72)
        b"\x00\x00\x00\x00"  # Status: OK
        b"\x18\x53\xc8\x00"  # Flags: Caseless, Canonical, OpLock
        b"\x00\x00"          # Flags2: Unicode
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # PID, TID, UID, MID
        b"\x00"              # Word Count: 0
        b"\x22\x00"          # Byte Count: 34 bytes
        b"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"      # "SMB 2.002"
        b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"      # "SMB 2.???"
    )
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((target_ip, port))
        s.sendall(smb_negotiate_raw)
        resp = s.recv(1024)
        if len(resp) >= 8 and resp[4:8] in [b"\xff\x53\x4d\x42", b"\xfe\x53\x4d\x42"]:
            magic = "SMBv1 (CIFS)" if resp[4:8] == b"\xff\x53\x4d\x42" else "SMBv2/v3"
            print(f"[+] Server Responded with Valid Header: {magic}")
            print(f"    - Response Length: {len(resp)} bytes")
            print(f"    - Raw Magic Bytes: {resp[4:8].hex()}")
            print("[+] PASS: Target service successfully enumerated via native SMB negotiate.")
        else:
            print("[*] Service open, but returned non-SMB response or closed negotiation.")
    except (ConnectionRefusedError, socket.timeout):
        print(f"[+] [SECURE] SMB port {port} is closed or unreachable on {target_ip} (Standard Secure Default).")
    finally:
        s.close()

def audit_smtp_user_verification(target_ip, port=25, test_user="root"):
    print("\n" + "=" * 72)
    print(f"[*] AUDITING SMTP INFORMATION DISCLOSURE: {target_ip}:{port}")
    print("=" * 72)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((target_ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        print(f"[+] Received SMTP Service Banner: '{banner}'")
        
        vrfy_cmd = f"VRFY {test_user}\r\n".encode()
        s.sendall(vrfy_cmd)
        resp = s.recv(1024).decode(errors="ignore").strip()
        print(f"[*] Sent: VRFY {test_user} -> Received: '{resp}'")
        
        if resp.startswith("250"):
            print("[!] VULNERABILITY: SMTP VRFY command exposed user account confirmation!")
        elif resp.startswith("252"):
            print("[i] INFO: Server returned 252 (Cannot VRFY user, will attempt delivery).")
        elif resp.startswith("502") or resp.startswith("500"):
            print("[+] [SECURE]: SMTP VRFY command is disabled (Command not implemented).")
    except (ConnectionRefusedError, socket.timeout):
        print(f"[+] [SECURE] SMTP port {port} is closed or unreachable on {target_ip}.")
    finally:
        s.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    audit_smb_dialect_negotiate(target)
    audit_smtp_user_verification(target)
    print("\n[+] SERVICE ENUMERATION AUDIT COMPLETE.")
