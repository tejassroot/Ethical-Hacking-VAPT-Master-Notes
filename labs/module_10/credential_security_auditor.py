#!/usr/bin/env python3
"""
================================================================================
MODULE 10 LAB: CREDENTIAL SECURITY & PASSWORD ENTROPY AUDITOR
PURPOSE: Demonstrates cryptographic KDF stretching, salt mechanics, and entropy analysis.
COMPLIANCE: Aligned with NIST SP 800-63B Guidelines.
================================================================================
"""

import hashlib
import os
import math
import time
import sys

def calculate_password_entropy(password):
    pool = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if has_lower:   pool += 26
    if has_upper:   pool += 26
    if has_digit:   pool += 10
    if has_special: pool += 33

    if pool == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

def benchmark_kdf_stretching():
    print("=" * 72)
    print("[*] STEP 1: BENCHMARKING HASH STRETCHING (FAST HASH VS KDF)")
    print("=" * 72)

    password = b"CompanySummer2026!"
    salt = os.urandom(16)

    # 1. Single-Round Salted SHA-256 (Fast / Insecure)
    t0 = time.perf_counter()
    for _ in range(10000):
        _ = hashlib.sha256(salt + password).digest()
    t1 = time.perf_counter()
    sha256_rate = 10000 / (t1 - t0)
    print(f"[+] Single-Round SHA-256 Rate:    {sha256_rate:,.0f} hashes/second on single CPU core")

    # 2. Modern PBKDF2-HMAC-SHA256 (600,000 Iterations - NIST Recommended)
    t0 = time.perf_counter()
    kdf_hash = hashlib.pbkdf2_hmac('sha256', password, salt, iterations=600000)
    t1 = time.perf_counter()
    pbkdf2_duration = (t1 - t0) * 1000
    print(f"[+] PBKDF2 (600,000 iters) Time:  {pbkdf2_duration:.2f} ms per single password verification")
    print(f"[+] Derived Key Hash:            {kdf_hash.hex()[:32]}...[REDACTED]")
    print(f"[i] Architectural Impact: An attacker testing 1 Billion guesses requires ~7,000 days of CPU time!")

def audit_password_policy_compliance(password):
    print("\n" + "=" * 72)
    print(f"[*] STEP 2: NIST SP 800-63B PASSWORD POLICY AUDIT")
    print("=" * 72)

    entropy = calculate_password_entropy(password)
    length = len(password)
    
    print(f"[*] Candidate Password:  {'*' * length} (Length: {length} chars)")
    print(f"[*] Estimated Entropy:   {entropy} bits")

    is_compliant = True
    if length < 8:
        print("[!] FAIL: Password shorter than NIST minimum (8 characters).")
        is_compliant = False
    elif length >= 15:
        print("[+] PASS: Excellent length (>= 15 characters, suitable for privileged accounts).")
    else:
        print("[+] PASS: Meets standard user minimum length (>= 8 characters).")

    if entropy < 40.0:
        print("[!] WARNING: Low entropy (< 40 bits). Highly susceptible to dictionary cracking.")
    else:
        print("[+] PASS: Sufficient cryptographic entropy.")

    print("\n[+] CREDENTIAL AUDIT COMPLETE.")

if __name__ == "__main__":
    benchmark_kdf_stretching()
    test_pass = sys.argv[1] if len(sys.argv) > 1 else "EnterprisePass2026!"
    audit_password_policy_compliance(test_pass)
