#!/usr/bin/env python3
"""
Wireless Security & 802.11 Protocol Auditor
Standalone security tool for analyzing 802.11 cryptographic key derivations,
PMKID calculations, RSN Information Elements (802.11w PMF), and Deauth floods.

Conforms to IEEE 802.11-2020 and Hashcat Mode 22000 specifications.
"""

import sys
import os
import hmac
import hashlib
import binascii
import struct
import time
from typing import Dict, List, Tuple, Optional

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive credentials/hashes to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """
    Derives the 256-bit Pairwise Master Key (PMK) using PBKDF2.
    Formula: PBKDF2(HMAC-SHA1, Passphrase, SSID, iterations=4096, dkLen=32)
    """
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

def custom_prf512(key: bytes, prefix: bytes, data: bytes) -> bytes:
    """
    IEEE 802.11 PRF-512 implementation using HMAC-SHA1.
    Derives 512 bits (64 octets) of pseudo-random data.
    """
    out = b""
    i = 0
    while len(out) < 64:
        msg = prefix + b"\x00" + data + bytes([i])
        out += hmac.new(key, msg, hashlib.sha1).digest()
        i += 1
    return out[:64]

def derive_ptk(pmk: bytes, ap_mac: str, sta_mac: str, anonce: bytes, snonce: bytes) -> Dict[str, bytes]:
    """
    Derives the Pairwise Transient Key (PTK) and partitions it into KCK, KEK, and TK.
    Formula: PRF-512(PMK, "Pairwise key expansion", Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
    """
    clean_ap = binascii.unhexlify(ap_mac.replace(":", ""))
    clean_sta = binascii.unhexlify(sta_mac.replace(":", ""))
    
    b_macs = min(clean_ap, clean_sta) + max(clean_ap, clean_sta)
    b_nonces = min(anonce, snonce) + max(anonce, snonce)
    data = b_macs + b_nonces
    
    ptk_raw = custom_prf512(pmk, b"Pairwise key expansion", data)
    
    return {
        "KCK": ptk_raw[0:16],    # Bits 0-127: Key Confirmation Key (MIC calculation)
        "KEK": ptk_raw[16:32],   # Bits 128-255: Key Encryption Key (GTK wrapping)
        "TK": ptk_raw[32:48],    # Bits 256-383: Temporal Key (AES-CCMP payload)
        "PTK_FULL": ptk_raw
    }

def calculate_pmkid(pmk: bytes, ap_mac: str, sta_mac: str) -> str:
    """
    Calculates 128-bit PMKID for 802.11r / WPA2 Fast BSS Transition.
    Formula: HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)
    """
    clean_ap = binascii.unhexlify(ap_mac.replace(":", ""))
    clean_sta = binascii.unhexlify(sta_mac.replace(":", ""))
    salt = b"PMK Name" + clean_ap + clean_sta
    digest = hmac.new(pmk, salt, hashlib.sha1).digest()
    return binascii.hexlify(digest[:16]).decode('ascii')

def format_hashcat_22000(pmkid_hex: str, ap_mac: str, sta_mac: str, ssid: str) -> str:
    """Formats output conforming to modern Hashcat Hash-Mode 22000 (PMKID line)."""
    clean_ap = ap_mac.replace(":", "").lower()
    clean_sta = sta_mac.replace(":", "").lower()
    clean_ssid_hex = binascii.hexlify(ssid.encode('utf-8')).decode('ascii')
    # Format: WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***
    return f"WPA*01*{pmkid_hex}*{clean_ap}*{clean_sta}*{clean_ssid_hex}***"

def parse_rsn_capabilities(rsn_cap_int: int) -> Dict[str, any]:
    """
    Parses RSN Capabilities 16-bit integer (IEEE 802.11w Protected Management Frames).
    Bit 6: Management Frame Protection Required (MFPR)
    Bit 7: Management Frame Protection Capable (MFPC)
    """
    mfpc = bool(rsn_cap_int & (1 << 7))
    mfpr = bool(rsn_cap_int & (1 << 6))
    
    if mfpr:
        status = "HARDENED (802.11w PMF Required - Immune to Deauth Spoofing)"
        risk = "LOW"
    elif mfpc:
        status = "TRANSITION (802.11w PMF Capable - Optional, Deauth Risk Present)"
        risk = "MEDIUM"
    else:
        status = "LEGACY VULNERABLE (No PMF - Vulnerable to Deauth Flooding)"
        risk = "HIGH"
        
    return {
        "RSN_Cap_Hex": f"0x{rsn_cap_int:04x}",
        "MFPC_Capable": mfpc,
        "MFPR_Required": mfpr,
        "Status": status,
        "Risk_Level": risk
    }

class WirelessDeauthDetector:
    """Detects deauthentication frame burst attacks using a sliding time window."""
    def __init__(self, threshold: int = 15, time_window_seconds: float = 2.0):
        self.threshold = threshold
        self.time_window = time_window_seconds
        self.events: List[Tuple[float, str, str]] = [] # (timestamp, src_mac, reason_code)

    def record_frame(self, timestamp: float, src_mac: str, reason_code: int) -> Optional[Dict[str, any]]:
        self.events.append((timestamp, src_mac, str(reason_code)))
        # Prune older than time window
        cutoff = timestamp - self.time_window
        self.events = [e for e in self.events if e[0] >= cutoff]
        
        # Count frames from src_mac
        src_events = [e for e in self.events if e[1] == src_mac]
        if len(src_events) >= self.threshold:
            return {
                "alert": "DEAUTH_FLOOD_DETECTED",
                "attacker_mac": src_mac,
                "frame_count": len(src_events),
                "duration_seconds": round(src_events[-1][0] - src_events[0][0], 2),
                "reason_code": reason_code,
                "mitigation": "Enforce IEEE 802.11w (PMF) on Access Point and isolate MAC."
            }
        return None

def run_self_tests():
    print("[*] Running Wireless Security Auditor Self-Tests...")
    
    # Test 1: PMK derivation check with known test vector
    # WPA standard test vector: Passphrase "password", SSID "IEEE"
    pmk = derive_pmk("password", "IEEE")
    assert len(pmk) == 32, "PMK must be 32 bytes (256 bits)"
    assert pmk.hex().startswith("f42c"), f"PMK mismatch on test vector: {pmk.hex()}"
    print(f"[+] Test 1 Passed: PMK derived correctly: {redact_string(pmk.hex())}")

    # Test 2: PMKID calculation
    ap_mac = "00:11:22:33:44:55"
    sta_mac = "AA:BB:CC:DD:EE:FF"
    pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
    assert len(pmkid) == 32, "PMKID must be 32 hex chars (128 bits)"
    print(f"[+] Test 2 Passed: PMKID generated: {redact_string(pmkid)}")

    # Test 3: Hashcat 22000 format
    hc_line = format_hashcat_22000(pmkid, ap_mac, sta_mac, "CorporateWLAN")
    assert hc_line.startswith("WPA*01*"), "Invalid Hashcat 22000 header"
    print(f"[+] Test 3 Passed: Hashcat 22000 string: {redact_string(hc_line, 15)}")

    # Test 4: PTK and KCK/KEK/TK derivation
    anonce = b"\x01" * 32
    snonce = b"\x02" * 32
    ptk_dict = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
    assert len(ptk_dict["KCK"]) == 16, "KCK must be 16 bytes (128 bits)"
    assert len(ptk_dict["KEK"]) == 16, "KEK must be 16 bytes (128 bits)"
    assert len(ptk_dict["TK"]) == 16, "TK must be 16 bytes (128 bits)"
    print(f"[+] Test 4 Passed: PTK partitioned into KCK, KEK, TK successfully.")

    # Test 5: RSN Capabilities (802.11w PMF)
    # Bit 6=1, Bit 7=1 -> 0x00C0
    cap_hardened = parse_rsn_capabilities(0x00C0)
    assert cap_hardened["MFPR_Required"] is True
    assert cap_hardened["Risk_Level"] == "LOW"
    
    cap_vulnerable = parse_rsn_capabilities(0x0000)
    assert cap_vulnerable["MFPR_Required"] is False
    assert cap_vulnerable["Risk_Level"] == "HIGH"
    print(f"[+] Test 5 Passed: RSN Capabilities & 802.11w evaluation accurate.")

    # Test 6: Deauth Flood Detection
    detector = WirelessDeauthDetector(threshold=5, time_window_seconds=1.0)
    now = time.time()
    alert_triggered = False
    for i in range(6):
        res = detector.record_frame(now + (i * 0.05), "DE:AD:BE:EF:00:01", 7)
        if res:
            alert_triggered = True
            break
    assert alert_triggered is True, "Deauth detector must fire after exceeding threshold"
    print(f"[+] Test 6 Passed: Deauth flood detector triggered successfully.")
    
    print("[*] All Wireless Security Auditor tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
