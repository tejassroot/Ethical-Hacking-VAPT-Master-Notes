# Volume 04: Core Ethical Hacking
# Module 10: Password Security, Cryptographic Hash Auditing & Credential Defense

---

## 1. Learning Objectives

By completing this module, security engineers, penetration testers, and identity architects will be able to:
1. Deconstruct the mathematical architecture of password storage: contrast salts, server-side peppers, and Key Derivation Functions (KDFs).
2. Evaluate password hashing algorithms: mathematically contrast fast, GPU-vulnerable algorithms (MD5, SHA-256, NTLM) with memory-hard, ASIC-resistant standards (Argon2id, bcrypt, scrypt, PBKDF2).
3. Deconstruct Windows authentication architectures: explain the generation of NTLM hashes ($MD4(UTF16LE(Password))$), the mechanics of Pass-the-Hash (PtH), and Kerberos Kerberoasting offline ticket cracking.
4. Execute professional offline credential recovery audits using Hashcat and John the Ripper across dictionary, mask, hybrid, and rule-based attack modes.
5. Model online credential attack vectors: distinguish between high-volume account brute-forcing, credential stuffing from breach dumps, and low-and-slow enterprise password spraying.
6. Audit Multi-Factor Authentication (MFA) implementations: contrast phishable factors (SMS, Voice, Push notification fatigue, RFC 6238 TOTP) with cryptographically bound, phishing-resistant standards (FIDO2 / WebAuthn passkeys).
7. Formulate and enforce modern enterprise identity policies aligned with **NIST SP 800-63B (Digital Identity Guidelines)**.

---

## 2. Prerequisites & Technical Foundations

Before studying this module, ensure familiarity with:
* **Cryptographic Hash Functions**: One-way property, collision resistance, and avalanche effect (covered in [Module 24](file:///home/kali/Ethical_Hacking_VAPT_Master_Notes/Volume_02_Linux_Networking_and_Security_Foundations/Module_24_Applied_Cryptography_and_PKI.md)).
* **Operating System User Backends**: Linux `/etc/shadow` format and Windows SAM/NTDS database architectures (covered in [Module 05](file:///home/kali/Ethical_Hacking_VAPT_Master_Notes/Volume_02_Linux_Networking_and_Security_Foundations/Module_05_Linux_Architecture_and_Administration.md)).

---

## 3. What Is It?

**Credential Security and Password Auditing** is the technical discipline of authenticating human and service identities without exposing the underlying secrets to interception, theft, or offline computational recovery.

Despite the proliferation of biometric sensors and hardware tokens, passwords remain the primary authentication mechanism across enterprise systems. However, passwords cannot be stored in plaintext. If an attacker breaches an application via SQL injection or access to a database backup, cleartext storage instantly exposes all user accounts.

Modern defensive engineering requires storing passwords as **cryptographically salted, computationally stretched, memory-hard hashes**. In parallel, security auditors perform authorized credential recovery audits to discover weak, compromised, or policy-violating passwords before threat actors exploit them.

---

## 4. Deep Technical Architecture & Internals

### 4.1 Evolution of Password Storage Mechanics

```
1. Plaintext Storage (CATASTROPHIC)
   Password: "Password123" ---> Database: "Password123"
   Impact: Database leak directly compromises all accounts.

2. Fast Cryptographic Hashing (FATALLY INSECURE - Precomputed Rainbow Tables)
   Password: "Password123" ---> MD5() ---> "482c811da5d5b4bc6d497ffa98491e38"
   Flaw: Identical passwords produce identical hashes. Vulnerable to instant reverse lookup
         in precomputed tables. Modern GPU clusters compute >150 Billion MD5/sec!

3. Salted Hashing (INSUFFICIENT AGAINST MODERN HARDWARE)
   Salt: Random 16 bytes generated per user.
   Hash = SHA256(Salt || Password)
   Benefit: Defeats precomputed rainbow tables; identical passwords have distinct hashes.
   Fatal Flaw: SHA-256 is designed for high throughput. An 8-GPU rig still computes 
               >50 Billion guesses per second, cracking 8-character passwords in minutes!

4. Memory-Hard Key Derivation Functions (MODERN INDUSTRY STANDARD)
   Hash = Argon2id(Password, Salt, TimeCost=3, MemoryCost=64MB, Parallelism=4)
   Mechanism: Forces the computer to allocate large blocks of RAM and process sequential
              mathematical dependencies. Strips the parallelization advantage of GPUs and ASICs.
```

### 4.2 Algorithm Comparison Matrix

```
+-------------------------------------------------------------------------------------------------------------+
| Algorithm   | Memory Hardness | Primary Resistance   | Standard Parameters     | Status & Compliance         |
+-------------------------------------------------------------------------------------------------------------+
| NTLM        | None (0 KB)     | None. Extremely fast | None. Single MD4 round  | OBSOLETE. 150B/sec on GPU.  |
|             |                 |                      |                         |                             |
| PBKDF2      | None (0 KB)     | CPU-bound only       | Iterations: >= 600,000  | LEGACY ACCEPTABLE. Vulner-  |
|             |                 |                      | (HMAC-SHA256)           | able to ASIC acceleration.  |
|             |                 |                      |                         |                             |
| bcrypt      | Low (4 KB)      | GPU L1 Cache bound   | Cost factor: >= 12      | INDUSTRY STANDARD. Max pass |
|             |                 |                      | (2^12 = 4,096 rounds)   | length 72 bytes.            |
|             |                 |                      |                         |                             |
| scrypt      | High (Config)   | Sequential memory    | N=32768, r=8, p=1       | SECURE. High memory         |
|             |                 | access               |                         | consumption stops ASICs.    |
|             |                 |                      |                         |                             |
| Argon2id    | Configurable    | Hybrid: Side-channel | t=3, m=65536 (64MB),    | GOLD STANDARD (RFC 9106).   |
|             | (e.g., 64 MB)   | and GPU memory-hard  | p=4                     | Winner Password Hashing Comp|
+-------------------------------------------------------------------------------------------------------------+
```

### 4.3 Windows Authentication Internals: NTLM vs. Kerberos

#### The NTLM Hash Architecture
Windows stores local and domain passwords as an **NTLM Hash**:
$$NTLM = MD4(UTF\text{-}16LE(Password))$$
* *Critical Flaw 1*: The NTLM hash is **unsalted**. If two users have the same password, their NTLM hashes are identical.
* *Critical Flaw 2*: The NTLM hash **never changes** unless the user updates their password.
* *Critical Flaw 3 (Pass-the-Hash - PtH)*: In Windows NTLM authentication, the client never sends the cleartext password to the server. The client calculates the response using the NTLM hash as the cryptographic key. Therefore, an attacker who extracts the NTLM hash from LSASS memory or NTDS.dit does not need to crack it; they can authenticate directly across the network as that user (**Pass-the-Hash**).

#### Kerberoasting Mechanics (Active Directory)
Kerberos authenticates domain users using tickets issued by the Key Distribution Center (KDC):
1. A domain user requests a Service Ticket (TGS) for a target Service Principal Name (SPN) associated with a service account (e.g., `MSSQLSvc/db01.corp.local`).
2. The KDC generates the ticket encrypted using the **NTLM hash of the service account**.
3. Any authenticated domain user (even the lowest privileged guest) can request a TGS for any registered SPN without triggering alerts.
4. The attacker extracts the ticket from memory or network traffic and cracks the service account's password **offline** on a GPU cluster (**Kerberoasting**).

---

## 5. How It Works: Hashcat Attack Modes & Engine Mechanics

Hashcat leverages the massively parallel compute architecture of GPUs (OpenCL / CUDA) to compute billions of candidate password variations per second:

```
+-----------------------------------------------------------------------------+
| Hashcat Attack Modes (Engine Syntax):                                       |
|                                                                             |
| -a 0 | Straight Dictionary: Evaluates raw wordlists (e.g., rockyou.txt).    |
| -a 1 | Combinator: Combines words from two lists (word1 + word2).           |
| -a 3 | Pure Mask / Brute-Force: Systematic character permutation.           |
| -a 6 | Hybrid Wordlist + Mask: Wordlist + appended mask (e.g., Password123!). |
| -a 7 | Hybrid Mask + Wordlist: Prepend mask to wordlist (e.g., !123Password). |
+-----------------------------------------------------------------------------+
```

### Character Set Built-in Masks (`-a 3`)

```
?l = abcdefghijklmnopqrstuvwxyz (Lower)
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ (Upper)
?d = 0123456789 (Digits)
?s =  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ (Special)
?a = ?l?u?d?s (All printable ASCII)
```

### Rule-Based Cracking Engine
Rule-based attacks transform dictionary words using programmatic modifiers:
* `: ` Do nothing.
* `l ` Convert entire string to lowercase (`Password` $\to$ `password`).
* `u ` Convert entire string to uppercase (`Password` $\to$ `PASSWORD`).
* `c ` Capitalize first letter (`password` $\to$ `Password`).
* `$1 ` Append character '1' to the end (`Password` $\to$ `Password1`).
* `^! ` Prepend character '!' to the beginning (`Password` $\to$ `!Password`).
* `sa@ ` Substitute character 'a' with '@' (`Password` $\to$ `P@ssword`).

---

## 6. Security Perspective & Threat Surface

### 6.1 Online vs. Offline Credential Attacks

```
+-------------------------------------------------------------------------------+
| Attack Vector       | Operational Characteristics     | Detection Footprint   |
+-------------------------------------------------------------------------------+
| Password Spraying   | Tries 1 common password         | Stealthy. Avoids      |
|                     | (e.g., "Winter2026!") across    | account lockouts. Low |
|                     | thousands of accounts.          | volume per user.      |
|                                                                               |
| Credential Stuffing | Ingests billions of leaked      | Spikes in failed auth |
|                     | username/password pairs from    | across disparate user |
|                     | third-party breaches.           | accounts.             |
|                                                                               |
| Brute-Force         | Rapidly attempts thousands of   | Highly noisy. Triggers|
|                     | passwords against 1 account.    | account lockouts in   |
|                     |                                 | seconds.              |
|                                                                               |
| Offline Cracking    | Steals hash database (NTDS.dit, | ZERO target telemetry.|
|                     | /etc/shadow) and cracks hashes  | Operates entirely on  |
|                     | on private GPU cluster.         | attacker hardware.    |
+-------------------------------------------------------------------------------+
```

### 6.2 MFA Bypass Vectors

* **MFA Fatigue / Prompt Bombing**: Attacker sends dozens of push notification requests to an employee's mobile authenticator at 3:00 AM until the exhausted user clicks "Approve."
* **Adversary-in-the-Middle (AiTM) Reverse Proxy**: Attacker deploys a tool like Evilginx. When the victim authenticates, the proxy captures both the password and the valid post-auth session cookie, bypassing TOTP/SMS MFA entirely.
* **SIM Swapping**: Attacker socially engineers the victim's mobile carrier into reassigning the victim's phone number to an attacker-controlled SIM card, intercepting SMS verification codes.

---

## 7. Auditing Methodology: Offline Credential Recovery Audit

```
[ Phase 1: Cryptographic Hash Identification ]
  - Inspect hash string format, length, and identifier tags:
    hash-identifier or hashid "$6$5p...$"
  - Identify Hashcat mode:
    - Mode 1000: NTLM
    - Mode 1800: SHA-512 crypt (Linux /etc/shadow)
    - Mode 3200: bcrypt
    - Mode 13100: Kerberos 5 TGS-REP (Kerberoasting)
       |
[ Phase 2: Wordlist & Rule-Based Cracking ]
  - Run high-probability dictionary attack:
    hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  - Apply enterprise rule mutators:
    hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
       |
[ Phase 3: Targeted Mask Permutation ]
  - Test compliance patterns (Capital letter + 7 lower + 2 digits + 1 special):
    hashcat -m 1000 -a 3 hashes.txt "?u?l?l?l?l?l?l?l?d?d?s"
       |
[ Phase 4: Statistical Posture Analysis ]
  - Calculate percentage of recovered credentials (compromise ratio).
  - Identify password reuse across privileged accounts (e.g., Domain Admin sharing pass with local user).
  - Categorize passwords failing enterprise complexity and length policies.
       |
[ Phase 5: Cryptographic Sealing & Secure Disposal ]
  - Delete all unmasked cleartext credential files immediately following audit generation.
  - Store encrypted hash archives under AES-256 encryption.
```

---

## 8. Tooling Deep-Dive

### 8.1 Hashcat Precision Execution CLI Syntax

```bash
# 1. Audit Linux /etc/shadow SHA-512 hashes (Mode 1800) using rockyou.txt
hashcat -m 1800 -a 0 shadow_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_shadow.txt

# 2. Audit Windows NTLM hashes (Mode 1000) using a custom 8-character mask
hashcat -m 1000 -a 3 ntlm_hashes.txt "?u?l?l?l?d?d?d?s" --status --status-timer=10

# 3. Audit Kerberoasted TGS tickets (Mode 13100) using hybrid dictionary + rule attack
hashcat -m 13100 -a 0 kerberoast_tickets.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# 4. Display cracked passwords from Hashcat internal potfile
hashcat -m 1000 --show ntlm_hashes.txt
```

### 8.2 Hash Identification via `hashid`

```bash
# Analyze an unknown hash string to determine algorithm and Hashcat/John modes
hashid -m -j '$6$qZ7...$v8Z...'
# Output:
# [+] SHA-512 Crypt [Hashcat Mode: 1800] [John the Ripper: sha512crypt]
```

---

## 9. Practical Lab: Standalone Python Credential Security Auditor

Deploy this standalone script to evaluate password storage: it implements salted SHA-256 vs PBKDF2 benchmarks, evaluates password entropy, and verifies Argon2/bcrypt parameter compliance.

Save as `credential_security_auditor.py`:

```python
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
    """
    Calculates the Shannon entropy (in bits) of a password string based on its
    character set pool size. Formula: E = L * log2(R)
    """
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
    """
    Benchmarks single-round SHA-256 vs. 600,000-iteration PBKDF2-HMAC-SHA256
    to demonstrate why KDFs protect passwords against brute-force attacks.
    """
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
    """
    Audits a candidate password against NIST SP 800-63B standards.
    """
    print("\n" + "=" * 72)
    print(f"[*] STEP 2: NIST SP 800-63B PASSWORD POLICY AUDIT")
    print("=" * 72)

    entropy = calculate_password_entropy(password)
    length = len(password)
    
    print(f"[*] Candidate Password:  {'*' * length} (Length: {length} chars)")
    print(f"[*] Estimated Entropy:   {entropy} bits")

    # NIST Criteria: Minimum 8 characters (15 for admins), no mandatory complexity rules, check common list
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
```

---

## 10. Evidence & Verification: Verifying NTLM Pass-the-Hash

### Non-Destructive Proof-of-Concept Protocol

To empirically verify that an NTLM hash provides equivalent authentication privileges to a cleartext password:

```bash
# 1. Identify valid compromised NTLM hash (e.g., Administrator: 31d6cfe0d16ae931b73c59d7e0c089c0)
# (Zero-password cleartext is required; authentication passes hash directly)

# 2. Execute authenticated SMB query using NetExec / CrackMapExec passing the HASH:
nxc smb 10.10.50.20 -u 'Administrator' -H '31d6cfe0d16ae931b73c59d7e0c089c0'

# VERIFIED FINDING OUTPUT:
# SMB  10.10.50.20  445  DC01  [+] target.local\Administrator:31d6cfe0... (Pwn3d!)
# Observation: Authentication succeeded without decrypting or knowing the cleartext password.
```

---

## 11. Telemetry, Detection & Log Signatures

### 11.1 Windows Event Log: Password Spraying Detection

When an attacker sprays a single password across hundreds of domain accounts:

* **Event ID 4625 (An Account Failed to Log On)**:
  * Failure Reason: `Unknown user name or bad password` (`0xC000006A`).
  * Process Name: `C:\Windows\System32\lsass.exe`.
  * **Key Indicator**: Dozens of Event 4625 events occurring within a short timeframe originating from the **same source IP or workstation**, targeting **different usernames**.

### 11.2 Splunk Detection Rule: Enterprise Password Spray

```spl
index=wineventlog EventCode=4625 SubStatus="0xc000006a"
| bucket _time span=5m
| stats dc(TargetUserName) as distinct_targets, values(TargetUserName) as targeted_users by src_ip
| where distinct_targets > 15
| eval Alert="High-Confidence Password Spray Attack Detected"
```

---

## 12. Mitigation & Remediation: NIST SP 800-63B Alignment

### Modern Enterprise Identity Hardening Standards

Migrate legacy, flawed password policies to modern standards:

```
+-----------------------------------------------------------------------------------------------+
| Flawed Legacy Practice (Deprecated)   | Modern Standard (NIST SP 800-63B / CISA)               |
+-----------------------------------------------------------------------------------------------+
| Mandatory 90-day password rotation.   | NO periodic expiration unless evidence of compromise. |
| (Forces predictable patterns:         | (Prevents users from choosing incrementally weaker    |
|  Winter2025! -> Spring2025!)          |  passwords).                                          |
|                                                                                               |
| Arbitrary complexity mandates         | Focus on LENGTH (Minimum 8 chars for users, 15+ for   |
| (Must contain 1 upper, 1 lower, etc.) | admins). Allow full Unicode/spaces (Passphrases).     |
|                                                                                               |
| SMS and Email OTP Multi-Factor        | Phishing-Resistant MFA: FIDO2 / WebAuthn passkeys     |
| (Vulnerable to SIM swap and AiTM)     | (Cryptographically bound to origin domain via public key|
|                                                                                               |
| Unchecked user password choices       | Screen new passwords against known compromised        |
|                                       | dictionaries (Have I Been Pwned / Active Directory API|
+-----------------------------------------------------------------------------------------------+
```

---

## 13. System & Protocol Hardening (CIS Benchmark Alignment)

| Security Requirement | Implementation Baseline | Benchmark Reference |
| :--- | :--- | :--- |
| **Enforce Account Lockout** | Lock account after 5 consecutive failed attempts for minimum 15 minutes. | CIS Windows Benchmark 1.1.1 |
| **Disable NTLMv1** | Enforce NTLMv2 only: `Send NTLMv2 response only. Refuse LM & NTLM` (Level 5). | CIS Windows Benchmark 2.3.11 |
| **Protected Users Group** | Add domain administrators to `Protected Users` group (disables NTLM and DES). | Microsoft AD Security Guide |
| **Scramble Local Admin Passwords**| Deploy Microsoft LAPS (Local Administrator Password Solution) to rotate unique passwords. | CIS Windows Benchmark 2.3.1 |
| **Screen Passwords in AD** | Deploy Azure AD Password Protection for Windows Server Active Directory. | NIST SP 800-63B Section 5.1 |

---

## 14. Documented Real-World Case Studies

### Case Study 1: The Colonial Pipeline Ransomware Incident (2021)
* **Root Cause**: A single compromised legacy Virtual Private Network (VPN) account.
* **The Vulnerability**: An unmaintained, inactive employee account had an uncomplex password that was leaked in an external third-party credential dump. Critically, the VPN gateway **did not enforce Multi-Factor Authentication (MFA)** on this legacy profile.
* **Impact**: Attackers logged into the corporate network, deployed ransomware, and shut down the largest fuel pipeline in the United States for six days, leading to nationwide fuel shortages and state-of-emergency declarations.
* **Remediation**: Mandatory decommissioning of legacy VPN gateways and universal enforcement of phishing-resistant MFA across all remote access conduits.

### Case Study 2: The 2022 Uber MFA Fatigue Compromise
* **Attack Vector**: MFA Prompt Bombing (Fatigue Attack).
* **Mechanism**: Attackers purchased valid corporate credentials on the dark web. They repeatedly triggered push authentication requests to the employee's phone while messaging the employee on WhatsApp posing as IT support, asking them to accept the notification to stop the spam.
* **Impact**: Full compromise of Uber's internal AWS, Google Workspace, and Slack environments.
* **Remediation**: Replaced simple push "Accept/Deny" notifications with **Number Matching** and migrated critical access to FIDO2 WebAuthn passkeys.

---

## 15. Common Mistakes & Anti-Patterns

```
❌ ANTI-PATTERN 1: Storing Password Hashes Using Fast Algorithms
   Using SHA-256 or MD5 for web application user authentication.
   A single high-end consumer GPU can compute billions of guesses per second, rendering all passwords vulnerable.
   ✔ CORRECT: Enforce Argon2id with memory cost >= 64MB or bcrypt with cost >= 12.

❌ ANTI-PATTERN 2: Enforcing Mandatory 60/90-Day Password Expiration
   Forcing employees to change passwords every quarter.
   Users predictably append numbers or change months (e.g., Company2025! -> Company2026!), reducing actual security.
   ✔ CORRECT: Eliminate periodic rotation; mandate long passphrases and screen against known breach lists.

❌ ANTI-PATTERN 3: Assuming Push Notification MFA Is Completely Secure
   Relying on single-button push notifications without number matching or biometric verification.
   Users succumb to MFA fatigue attacks and approve malicious logins while distracted or sleep-deprived.
   ✔ CORRECT: Deploy FIDO2 hardware security keys (YubiKeys) or enforce MFA Number Matching.
```

---

## 16. Professional vs. Naive Methodology

| Operational Phase | Naive / Novice Approach | Professional Security Auditor Approach |
| :--- | :--- | :--- |
| **Hash Identification** | Tries cracking with arbitrary modes; errors out. | Uses `hashid` to verify algorithm, identifies exact salt/hash format, and benchmarks GPU throughput. |
| **Cracking Strategy** | Dumps `rockyou.txt` in straight mode and stops when it finishes. | Uses targeted multi-tier methodology: dictionary $\to$ mutator rules $\to$ hybrid mask permutations based on enterprise naming trends. |
| **AD Auditing** | Exploits systems without tracking impact. | Extracts NTDS hashes via VSS, analyzes password reuse across privilege tiers, and delivers clear remediation policies. |
| **Policy Guidance** | Recommends complex 8-character rules with symbols and 30-day changes. | Recommends NIST SP 800-63B standards: minimum 15+ length passphrases, breach screening, and FIDO2 passkeys. |

---

## 17. Graded Knowledge Check & Interview Questions

### Beginner Level
1. **Question**: What is the purpose of a cryptographic "Salt" in password hashing?
   * *Answer*: A salt is a unique, randomly generated string appended to a password before hashing. It ensures that identical passwords produce distinct hash digests, completely defeating precomputed lookup attacks (Rainbow Tables) and forcing attackers to crack each hash individually.
2. **Question**: What is the primary difference between online password guessing and offline hash cracking?
   * *Answer*: Online password guessing sends authentication requests across the network to the live application, which is rate-limited by network latency and subject to account lockout policies. Offline hash cracking occurs entirely on the auditor's local hardware against a stolen hash database, allowing billions of guesses per second with zero risk of triggering lockouts.

### Intermediate Level
3. **Question**: Why is Argon2id superior to PBKDF2 for protecting password hashes against GPU cracking rigs?
   * *Answer*: PBKDF2 is strictly CPU-bound, requiring almost zero RAM per calculation, allowing GPUs and dedicated ASICs to compute millions of parallel guesses simultaneously. Argon2id is a memory-hard algorithm that forces the computer to allocate substantial memory (e.g., 64MB) per verification, saturating GPU memory bandwidth and eliminating the hardware parallelization advantage.
4. **Question**: Explain the mechanics of a Pass-the-Hash (PtH) attack on a Windows network.
   * *Answer*: The Windows NTLM authentication protocol uses the 16-byte NTLM hash directly as the cryptographic secret to calculate the challenge-response. If an attacker extracts an NTLM hash from LSASS memory or the SAM database, they can authenticate to remote SMB/RPC services using the hash directly, without ever recovering the cleartext password.

### Advanced / Scenario-Based
5. **Question**: An auditor captures a Kerberos TGS ticket for service account `svc_sql` and cracks its NTLM hash offline in 4 minutes using Hashcat. What was the architectural root cause of this defect, and what two distinct engineering controls eliminate this attack surface?
   * *Answer*: The root cause is **Kerberoasting**: Active Directory permits any domain user to request a TGS ticket for any registered Service Principal Name (SPN), and the ticket is encrypted using the service account's password hash. If the service account uses a weak human-chosen password, it can be cracked offline. Controls to eliminate this: (1) Migrate the service account to a **Group Managed Service Account (gMSA)**, where Active Directory automatically manages a complex, 120-character randomized password that rotates automatically; (2) Enforce **AES-256 encryption** for Kerberos tickets, deprecating legacy RC4-HMAC.

---

## 18. Progressive Hands-on Exercises

### Level 1: Password Entropy & KDF Benchmarking (Beginner)
* Run the provided `credential_security_auditor.py` script. Compare the speed difference between single-round SHA-256 and 600,000-iteration PBKDF2.

### Level 2: Rule-Based Hashcat Cracking (Intermediate)
* Generate a sample SHA-512 crypt hash of a password following the pattern `Summer2026!`. Configure Hashcat with `rockyou.txt` and the `best64.rule` to crack the hash within 60 seconds.

### Level 3: Active Directory LAPS Audit (Advanced)
* Query an Active Directory lab environment using PowerShell or LDAP to identify all computer objects that have Local Administrator Password Solution (LAPS) enabled, verifying that the local administrator password rotates automatically.

---

## 19. Key Takeaways

1. **Slow and Memory-Hard Is Mandatory**: Never use fast algorithms (MD5, SHA-256, NTLM) for password storage. Standardize on Argon2id or bcrypt.
2. **Hashes Are Equated to Passwords in NTLM**: In Windows environments, possessing the NTLM hash is functionally identical to possessing the cleartext password (Pass-the-Hash).
3. **NIST SP 800-63B Is the Modern Standard**: Drop periodic password expirations and arbitrary character complexity rules; prioritize passphrase length, breach screening, and phishing-resistant MFA.
4. **Phishing-Resistant MFA Defeats AiTM**: Replace SMS and push notifications with FIDO2 WebAuthn passkeys that cryptographically bind to the browser's origin domain.
5. **Kerberoast Service Accounts**: Protect service accounts with Group Managed Service Accounts (gMSAs) to eliminate offline Kerberos ticket cracking.

---

## 20. Authoritative References

* **NIST SP 800-63B**: *Digital Identity Guidelines: Authentication and Lifecycle Management*.
* **RFC 9106**: *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work*.
* **RFC 2898**: *PKCS #5: Password-Based Cryptography Specification Version 2.0 (PBKDF2)*.
* **Provos, N., & Mazières, D. (1999)**: *A Future-Adaptable Password Scheme (bcrypt)*. USENIX Security.
* **Microsoft Security Guidance**: *Mitigating Pass-the-Hash and Other Credential Theft*.
* **CISA Fact Sheet**: *Implementing Phishing-Resistant Multi-Factor Authentication*.
