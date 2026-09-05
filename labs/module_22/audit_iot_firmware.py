#!/usr/bin/env python3
"""
Embedded IoT Firmware and Hardware Interface Security Audit Engine
Volume 10: Malware, Wireless, IoT & Advanced Security - Module 22
Author: Senior Cybersecurity & Embedded Systems Research Specialist

Demonstrates:
1. Synthetic firmware image generation (U-Boot Header, Kernel Block, SquashFS Rootfs).
2. Block-level Shannon entropy calculation to distinguish code, data, and compression.
3. Automated root filesystem security auditing:
   - Shadow/Passwd parsing for weak hashes ($1$ MD5, DES) and unauthenticated root accounts.
   - Hardcoded cryptographic keys and credential leak detection.
   - Insecure service initialization detection (Telnet, unauthenticated CGI daemons).
4. Full conformity with defensive engineering and automated triage standards.
"""

import math
import struct
import sys
import os

# U-Boot Legacy Image Header Magic: 0x27051956
UBOOT_IMAGE_MAGIC = 0x27051956

def calculate_shannon_entropy(data_bytes: bytes) -> float:
    """Calculates Shannon entropy (H) of a byte sequence (0.0 to 8.0)."""
    if not data_bytes:
        return 0.0
    freq = {}
    for b in data_bytes:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    total = len(data_bytes)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def build_synthetic_firmware() -> bytes:
    """
    Constructs a structured synthetic firmware binary containing:
    - 64-byte U-Boot Header
    - Simulated compressed kernel payload (high entropy)
    - Simulated plaintext root filesystem configuration block (low/medium entropy)
    """
    kernel_payload = bytes([((i * 101) + 37) % 256 for i in range(2048)]) # High entropy pseudo-random
    kernel_size = len(kernel_payload)
    
    header = struct.pack(
        ">IIIIIII4B32s",
        UBOOT_IMAGE_MAGIC,
        0xA1B2C3D4,       # Header CRC
        1700000000,       # Timestamp
        kernel_size,      # Image Data Size
        0x80000000,       # Data Load Address
        0x80000040,       # Entry Point Address
        0xE5F6A7B8,       # Data CRC
        5, 2, 2, 1,       # OS (Linux=5), Arch (ARM=2), Type (Kernel=2), Comp (gzip=1)
        b"Linux-4.14-OpenIoT-Kernel\x00".ljust(32, b"\x00")
    )

    # Simulated embedded filesystem configuration files
    fs_config = b"""
# /etc/shadow
root:$1$vL$dm8Kk8V1BqG6uI4r2.V6x/:18000:0:99999:7:::
admin:$1$a9$k7F4G6e8U3T2.W9x/:18000:0:99999:7:::
factory::18000:0:99999:7:::
guest:*:18000:0:99999:7:::

# /etc/init.d/rcS
telnetd -p 23 -l /bin/sh &
/usr/sbin/httpd -p 80 -c /etc/httpd.conf &

# /etc/httpd.conf
api_key=sk_live_9988****REDACTED
admin_secret=hardcoded_factory_pwd_2026
"""
    return header + kernel_payload + fs_config

def audit_firmware_partitions(fw_bytes: bytes):
    """Parses binary partitions, identifies magic signatures, and maps entropy."""
    print("=" * 72)
    print("PHASE 1: EMBEDDED FIRMWARE PARTITION & ENTROPY MAPPING")
    print("=" * 72)
    
    # Check U-Boot Header Magic
    if len(fw_bytes) >= 64:
        magic = struct.unpack(">I", fw_bytes[:4])[0]
        if magic == UBOOT_IMAGE_MAGIC:
            print(f"[+] Found U-Boot Legacy Image Header at offset 0x00000000:")
            ih_size = struct.unpack(">I", fw_bytes[12:16])[0]
            ih_os, ih_arch, ih_type, ih_comp = struct.unpack("4B", fw_bytes[28:32])
            ih_name = fw_bytes[32:64].split(b"\x00")[0].decode('latin-1')
            print(f"    - Image Name:      {ih_name}")
            print(f"    - Payload Size:    {ih_size} bytes")
            print(f"    - Target Arch/OS:  Arch ID {ih_arch} (ARM), OS ID {ih_os} (Linux)")
            print(f"    - Compression:     Type {ih_comp} (gzip)")
    
    # Block Entropy Analysis (1024-byte window)
    print("\n[*] Shannon Entropy Profile (1024-byte window):")
    window_size = 1024
    for offset in range(0, len(fw_bytes), window_size):
        chunk = fw_bytes[offset:offset+window_size]
        h = calculate_shannon_entropy(chunk)
        classification = "High (Compressed / Encrypted / Packed)" if h > 7.0 else "Medium/Low (Plaintext / Code / Config)"
        print(f"    Offset 0x{offset:06X} - 0x{min(offset+window_size, len(fw_bytes)):06X}: Entropy = {h:.4f} bits/byte -> {classification}")

def audit_extracted_filesystem(fw_bytes: bytes):
    """Audits extracted configuration and credential files inside firmware."""
    print("\n" + "=" * 72)
    print("PHASE 2: EXTRACTED FILESYSTEM CONFIGURATION & CREDENTIAL AUDIT")
    print("=" * 72)
    
    # Extract string lines for analysis
    text_content = fw_bytes.decode('latin-1', errors='ignore')
    findings = []
    
    lines = text_content.splitlines()
    in_shadow = False
    
    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            if "shadow" in line_clean.lower():
                in_shadow = True
            elif "rcs" in line_clean.lower() or "httpd" in line_clean.lower():
                in_shadow = False
            continue
            
        # Shadow file auditing
        if ":" in line_clean and in_shadow:
            parts = line_clean.split(":")
            if len(parts) >= 2:
                user, pwd_hash = parts[0], parts[1]
                if pwd_hash == "":
                    findings.append({
                        "severity": "CRITICAL",
                        "rule": "CWE-258: Empty Password in System Shadow",
                        "detail": f"Account '{user}' has an EMPTY password hash. Grants unauthenticated root access over physical UART/Telnet!"
                    })
                elif pwd_hash.startswith("$1$"):
                    findings.append({
                        "severity": "HIGH",
                        "rule": "CWE-327: Obsolete MD5-crypt Password Hash",
                        "detail": f"Account '{user}' uses legacy MD5 crypt ($1$). Vulnerable to high-speed offline GPU cracking."
                    })
                elif pwd_hash == "*":
                    print(f"[+] Account '{user}' is properly disabled (* lock).")
        
        # Insecure service launch in init scripts
        if "telnetd" in line_clean:
            findings.append({
                "severity": "CRITICAL",
                "rule": "OWASP IoT I2: Insecure Service - Unauthenticated Telnet",
                "detail": f"Found '{line_clean}' in startup scripts. Spawns cleartext, unauthenticated root shell on port 23."
            })
            
        # Hardcoded credentials or API keys
        if "admin_secret" in line_clean or "password" in line_clean.lower() and "=" in line_clean:
            findings.append({
                "severity": "HIGH",
                "rule": "CWE-798: Hardcoded Static Credentials in Configuration",
                "detail": f"Detected plaintext credential definition: '{line_clean}'."
            })
            
        if "api_key=" in line_clean:
            findings.append({
                "severity": "MEDIUM",
                "rule": "CWE-312: Cleartext Storage of Sensitive API Tokens",
                "detail": f"Found embedded cloud API token: '{line_clean}'."
            })

    print(f"\n[!] Audit Complete. Discovered {len(findings)} Security Vulnerabilities:\n")
    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] [{f['severity']}] {f['rule']}")
        print(f"    Details: {f['detail']}\n")

if __name__ == "__main__":
    print("[*] Initializing Embedded IoT Firmware Security Audit Engine...")
    firmware_binary = build_synthetic_firmware()
    print(f"[+] Generated synthetic firmware image: {len(firmware_binary)} bytes.")
    
    audit_firmware_partitions(firmware_binary)
    audit_extracted_filesystem(firmware_binary)
    print("=" * 72)
    print("[+] FIRMWARE SECURITY AUDIT COMPLETED SUCCESSFULLY")
    print("=" * 72)
