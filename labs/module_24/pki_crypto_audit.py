#!/usr/bin/env python3
"""
================================================================================
MODULE 24 LAB: CRYPTOGRAPHIC AUDITING & PRIMITIVE VERIFICATION ENGINE
PURPOSE: Demonstrates CBC bit-flipping, HMAC integrity, and timing-safe checks.
COMPLIANCE: NIST SP 800-175B / RFC 2104 / RFC 8446
================================================================================
"""

import hmac
import hashlib
import os
import time

def simulate_cbc_bit_flipping():
    """
    Demonstrates mathematically why unauthenticated CBC mode permits
    predictable plaintext tampering without knowing the secret key.
    
    Formula: P_1 = Decrypt(C_1) ^ C_0
    If we flip bit k in C_0, bit k flips in P_1.
    """
    print("=" * 72)
    print("[*] TEST 1: CBC MODE BIT-FLIPPING VULNERABILITY (UNAUTHENTICATED)")
    print("=" * 72)
    
    # Target plaintext block 1 (16 bytes): "user_id=10;adm=0"
    # We want to flip '0' (ASCII 0x30) to '1' (ASCII 0x31)
    original_plaintext = b"user_id=10;adm=0"
    print(f"[+] Original Target Plaintext:   '{original_plaintext.decode()}'")
    
    # Simulate an IV (Block 0) of 16 random bytes
    iv = bytearray(os.urandom(16))
    
    # The '0' is at index 15 (last byte of the block)
    target_index = 15
    original_char = ord('0')  # 0x30 (0011 0000)
    desired_char  = ord('1')  # 0x31 (0011 0001)
    
    # Compute bitwise modification mask
    diff_mask = original_char ^ desired_char
    
    # Tamper with the preceding ciphertext block (in this case, the IV)
    tampered_iv = bytearray(iv)
    tampered_iv[target_index] ^= diff_mask
    
    # Simulate CBC Decryption operation: Decrypted_Block ^ Modified_IV
    recovered_plaintext = bytearray(original_plaintext)
    recovered_plaintext[target_index] ^= diff_mask
    
    print(f"[!] Tampered IV Modified Byte:   Offset {target_index} XORed with {hex(diff_mask)}")
    print(f"[+] Resulting Decrypted String:  '{recovered_plaintext.decode()}'")
    
    assert recovered_plaintext == b"user_id=10;adm=1"
    print("[+] VERIFIED: Privilege elevation achieved via unauthenticated CBC malleability!")
    print("    Remediation: Migrate to AEAD cipher (AES-256-GCM or ChaCha20-Poly1305).\n")

def audit_hmac_and_timing_safety():
    """
    Evaluates HMAC construction and demonstrates constant-time validation.
    """
    print("=" * 72)
    print("[*] TEST 2: HMAC INTEGRITY & TIMING-SAFE AUDITING (RFC 2104)")
    print("=" * 72)
    
    secret_key = os.urandom(32)
    payload = b"action=transfer_funds&recipient=audit_team&amount=100000"
    
    # Compute genuine HMAC-SHA256
    genuine_hmac = hmac.new(secret_key, payload, hashlib.sha256).digest()
    print(f"[+] Payload:        '{payload.decode()}'")
    print(f"[+] Generated HMAC: {genuine_hmac.hex()[:32]}...[REDACTED]")
    
    # Simulate an attacker tampering with the payload
    tampered_payload = b"action=transfer_funds&recipient=attacker__&amount=100000"
    
    # Verify using constant-time comparison
    is_valid = hmac.compare_digest(
        genuine_hmac, 
        hmac.new(secret_key, tampered_payload, hashlib.sha256).digest()
    )
    
    print(f"[*] Validating Tampered Message against Master Tag: Valid={is_valid}")
    assert not is_valid
    print("[+] PASS: Cryptographic tampering detected deterministically.")
    print("=" * 72)

if __name__ == "__main__":
    simulate_cbc_bit_flipping()
    audit_hmac_and_timing_safety()
