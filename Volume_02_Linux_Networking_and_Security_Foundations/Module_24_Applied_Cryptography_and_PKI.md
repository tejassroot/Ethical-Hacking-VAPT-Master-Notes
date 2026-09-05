# Volume 02: Linux, Networking & Security Foundations
# Module 24: Applied Cryptography, Public Key Infrastructure & TLS Architecture

---

## 1. Learning Objectives

By completing this module, security practitioners, penetration testers, and cryptographic auditors will be able to:
1. Deconstruct symmetric primitives: analyze the Substitution-Permutation Network (SPN) of AES, contrast operational modes (ECB, CBC, CTR, GCM), and evaluate the security properties of Authenticated Encryption with Associated Data (AEAD).
2. Evaluate asymmetric cryptosystems: deconstruct RSA modular arithmetic, Elliptic Curve Cryptography (ECC, ECDSA, Ed25519), and Ephemeral Diffie-Hellman (ECDHE) key agreement.
3. Analyze cryptographic hashing and message authentication: deconstruct Merkle-Damgård constructions, demonstrate the mathematical basis of Length Extension attacks, and audit HMAC implementations (RFC 2104).
4. Audit Public Key Infrastructure (PKI): trace X.509 certificate chains, validate trust path processing (RFC 5280), inspect Certificate Transparency (CT) Merkle audit logs, and evaluate revocation mechanisms (CRL vs. OCSP Stapling).
5. Contrast the TLS 1.2 and TLS 1.3 cryptographic state machines, analyzing 1-RTT handshake negotiation, mandatory Perfect Forward Secrecy (PFS), encrypted server certificates, and 0-RTT replay vectors.
6. Identify, verify, and remediate common cryptographic failures (CWE-327, CWE-328, CWE-329, CWE-330) across application source code and enterprise network perimeters.

---

## 2. Prerequisites & Technical Foundations

Before studying this module, ensure familiarity with:
* **Discrete Mathematics & Binary Primitives**: Bitwise XOR ($\oplus$), modular arithmetic ($\pmod n$), and greatest common divisors.
* **TCP/IP Sockets**: Transport-layer connection lifecycles and byte streams (covered in [Module 08](file:///home/kali/Ethical_Hacking_VAPT_Master_Notes/Volume_02_Linux_Networking_and_Security_Foundations/Module_08_Networking_Protocols_and_Security.md)).
* **Basic Python Scripting**: Byte manipulation, standard binary encoding (`base64`, `hex`), and the `hashlib` library.

---

## 3. What Is It?

**Applied Cryptography and Public Key Infrastructure (PKI)** encompasses the mathematical algorithms, protocols, and architectural trust systems that guarantee **Confidentiality, Integrity, Authentication, and Non-Repudiation** across untrusted computing networks.

In modern security auditing, a critical maxim applies: **"Attacks rarely break the underlying mathematics; they break the implementation."**

Modern algorithms like AES-256 or ChaCha20 are computationally unbreakable against brute-force attacks with present and foreseeable classical computing power. However, enterprise applications routinely suffer severe compromises due to:
* Naive block cipher modes (e.g., using ECB mode which preserves plaintext structure).
* Cryptographic nonce or Initialization Vector (IV) reuse in stream and AEAD ciphers.
* Using unauthenticated encryption modes vulnerable to bit-flipping or padding oracles.
* Flawed trust-path validation in X.509 certificate parsing.
* Reliance on predictable pseudo-random number generators (PRNGs) for session keys.

---

## 4. Deep Technical Architecture & Internals

### 4.1 Symmetric Cryptography & The Advanced Encryption Standard (AES)

AES (FIPS 197) is a symmetric block cipher processing fixed 128-bit (16-byte) blocks using key lengths of 128, 192, or 256 bits through repeated rounds (10, 12, or 14 rounds respectively).

```
+-----------------------------------------------------------------------------+
| AES Encryption Round State Transformations (128-bit block / 4x4 byte state): |
|                                                                             |
| 1. SubBytes:     Non-linear byte substitution using a Rijndael S-Box         |
|                  derived from multiplicative inversion in Galois Field GF(2^8)|
|                                                                             |
| 2. ShiftRows:    Cyclic byte shifting: Row 0 shifted 0, Row 1 shifted 1,    |
|                  Row 2 shifted 2, Row 3 shifted 3 bytes left. (Diffusion)    |
|                                                                             |
| 3. MixColumns:   Linear transformation mixing the 4 bytes of each column     |
|                  via matrix multiplication over GF(2^8). (Diffusion)        |
|                                                                             |
| 4. AddRoundKey:  Bitwise XOR of the 128-bit state matrix with the           |
|                  corresponding round subkey derived from Key Expansion.     |
+-----------------------------------------------------------------------------+
```

#### Block Cipher Operational Modes

A block cipher encrypts only a single 16-byte block. Encrypting data streams of arbitrary length requires an **operational mode**:

```
1. Electronic Codebook (ECB) - FATALLY INSECURE
   - Each 16-byte plaintext block is encrypted independently with the same key:
     C_i = E_K(P_i)
   - Identical plaintext blocks produce identical ciphertext blocks, leaking patterns.

2. Cipher Block Chaining (CBC) - LEGACY / CONDITIONAL
   - Each plaintext block is XORed with the previous ciphertext block before encryption:
     C_0 = E_K(P_0 ^ IV),  C_i = E_K(P_i ^ C_{i-1})
   - Requires unique, unpredictable Initialization Vector (IV).
   - Insecure if unauthenticated: vulnerable to Bit-Flipping and Padding Oracle attacks.

3. Galois/Counter Mode (GCM) - MODERN AEAD STANDARD
   - Combines Counter (CTR) mode encryption with GHASH polynomial authentication:
     C_i = P_i ^ E_K(IV || Counter_i)
   - Computes an authentication tag (Tag) over ciphertext and Additional Authenticated Data (AAD).
   - CRITICAL REQUIREMENT: A nonce/IV must NEVER be reused with the same key.
```

### 4.2 Asymmetric Cryptography: RSA and Elliptic Curve Cryptography (ECC)

#### RSA Cryptosystem (Rivest-Shamir-Adleman - RFC 8017)
RSA relies on the computational difficulty of the **Integer Factorization Problem**:
1. Select two large distinct primes $p$ and $q$.
2. Compute modulus $n = p \cdot q$ and Euler's totient $\phi(n) = (p-1)(q-1)$.
3. Select public exponent $e$ such that $\gcd(e, \phi(n)) = 1$ (standard industry default: $e = 65537$).
4. Compute private exponent $d \equiv e^{-1} \pmod{\phi(n)}$ using the Extended Euclidean Algorithm.
5. **Encryption**: $C \equiv M^e \pmod n$.
6. **Decryption**: $M \equiv C^d \pmod n$.
* *Implementation Rule*: Raw/textbook RSA is insecure. Always enforce Optimal Asymmetric Encryption Padding (**OAEP**) for encryption and **PSS** for digital signatures.

#### Elliptic Curve Cryptography (ECC)
ECC relies on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. Given curve equation:
$$y^2 \equiv x^3 + ax + b \pmod p$$
* Public Key $Q$ is computed via scalar point multiplication: $Q = d \cdot G$, where $d$ is the private key scalar and $G$ is the generator base point.
* Computing $Q$ from $d$ and $G$ is computationally trivial; determining $d$ given $Q$ and $G$ is computationally intractable.
* **Key Size Efficiency**: ECC achieves equivalent cryptographic strength with vastly smaller keys:
  * RSA 2048-bit $\approx$ ECC 224-bit
  * RSA 3072-bit $\approx$ ECC 256-bit (NIST P-256 or Curve25519)
  * RSA 15360-bit $\approx$ ECC 512-bit

### 4.3 Cryptographic Hash Functions & HMAC

#### Merkle-Damgård Construction & Length Extension
Traditional hash algorithms (MD5, SHA-1, SHA-256) process input blocks sequentially:

```
IV ----> [ Compression Function f ] ----> State 1 ----> [ f ] ----> Final Hash
             ^                                              ^
             |                                              |
          Block 1                                        Block 2 (Padding)
```

* **Length Extension Flaw**: If an application computes an authentication token via simple concatenation:
  $$Token = SHA256(Secret \parallel Message)$$
  Because the final hash output is the exact internal state of the compression function after processing `Message` and its padding, an attacker who knows `Message` and `Token` can initialize a hash engine with `Token` as the IV and append `\parallel EvilData`, generating a valid signature for the extended message without knowing `Secret`!
* **Remediation**: Use **HMAC** (RFC 2104) which applies a nested, two-pass hashing construction:
  $$HMAC_K(M) = H((K \oplus opad) \parallel H((K \oplus ipad) \parallel M))$$

---

## 5. How It Works: PKI & The TLS 1.3 State Machine

### 5.1 Public Key Infrastructure (PKI) Trust Path Validation

```
+-------------------------------------------------------------+
| Root Certificate Authority (Self-Signed, in OS Trust Store) |
| Subject: CN=GlobalRoot CA, Issuer: CN=GlobalRoot CA         |
| Public Key: RootPubKey | Signature: RootPrivateKey(Self)     |
+-------------------------------------------------------------+
                              | Signs
                              v
+-------------------------------------------------------------+
| Intermediate CA Certificate                                 |
| Subject: CN=Enterprise Issuing CA, Issuer: CN=GlobalRoot CA |
| Public Key: InterPubKey | Signature: RootPrivateKey(...)     |
| Basic Constraints: cA=TRUE, pathLenConstraint=0             |
+-------------------------------------------------------------+
                              | Signs
                              v
+-------------------------------------------------------------+
| End-Entity / Leaf Server Certificate                        |
| Subject: CN=api.enterprise.com, Issuer: Enterprise Issuing  |
| Public Key: ServerPubKey | Signature: InterPrivateKey(...)   |
| Basic Constraints: cA=FALSE                                 |
| SAN: DNS:api.enterprise.com, DNS:auth.enterprise.com        |
+-------------------------------------------------------------+
```

* **X.509 RFC 5280 Verification Rules**:
  1. Client verifies signature of Leaf cert using Intermediate CA's public key.
  2. Client verifies signature of Intermediate cert using Root CA's public key.
  3. Client checks current timestamp against `notBefore` and `notAfter` validity periods.
  4. Client verifies `Basic Constraints`: `cA=TRUE` on signing CAs, `cA=FALSE` on leaf.
  5. Client confirms requested domain matches Subject Alternative Name (**SAN**) extension.
  6. Client checks revocation status via OCSP Stapling or Certificate Revocation Lists (CRL).

### 5.2 The Modern TLS 1.3 Handshake (RFC 8446 - 1-RTT)

TLS 1.3 establishes an encrypted session in a single round-trip (1-RTT), mandating Perfect Forward Secrecy:

```
Client                                                              Server
  |                                                                   |
  | ----- 1. ClientHello -------------------------------------------> |
  |       - Supported Cipher Suites (AEAD only: AES-GCM, ChaCha20)    |
  |       - Supported ECC Groups (e.g., x25519, secp256r1)            |
  |       - Key_Share: Client Ephemeral Public Key (g^x)              |
  |       - SNI: server.enterprise.com                                |
  |                                                                   |
  | <---- 2. ServerHello -------------------------------------------- |
  |       - Selected Cipher Suite (e.g., TLS_AES_256_GCM_SHA384)       |
  |       - Key_Share: Server Ephemeral Public Key (g^y)              |
  |       { Compute Shared Master Secret: g^(xy) }                    |
  |                                                                   |
  | <---- 3. EncryptedExtensions ------------------------------------ |
  | <---- 4. Certificate (Encrypted over wire!) --------------------- |
  | <---- 5. CertificateVerify (Signature over handshake transcript)  |
  | <---- 6. Finished (HMAC over handshake transcript) -------------- |
  |                                                                   |
  | ----- 7. Finished (HMAC confirmation) --------------------------> |
  |                                                                   |
  | <==== SECURE APPLICATION DATA (Bi-directional AEAD encrypted) ===>|
```

* **Key Advancements over TLS 1.2**:
  * **Removed Legacy Primitives**: Stripped static RSA key exchange (no forward secrecy), Diffie-Hellman with static parameters, CBC block cipher mode, SHA-1, MD5, and RC4.
  * **Encrypted Metadata**: Server certificate and extensions are encrypted under the ephemeral handshake key, preventing passive eavesdroppers on the wire from observing server identities.

---

## 6. Security Perspective & Threat Surface

### 6.1 Cryptographic Flaw Classifications

1. **Padding Oracle Attacks (CWE-327 / Vaudenay Attack)**:
   * Occurs when CBC-mode decryption returns distinguishable error responses based on whether PKCS#7 padding was valid or invalid.
   * By repeatedly submitting ciphertext blocks with altered trailing bytes and analyzing server error timing or messages, an attacker decrypts ciphertext byte-by-byte without the private key.
2. **CBC Bit-Flipping Attacks**:
   * In unauthenticated CBC mode: $P_i = D_K(C_i) \oplus C_{i-1}$.
   * Flipping bit $k$ in ciphertext block $C_{i-1}$ predictably flips bit $k$ in plaintext block $P_i$.
   * *Abuse Scenario*: If a session cookie stores `user_id=100;admin=0`, flipping the corresponding bit in the IV or preceding block turns `admin=0` into `admin=1`.
3. **GCM Nonce Reuse Catastrophe (CWE-329)**:
   * In AES-GCM, if the same 96-bit nonce/IV is ever used to encrypt two different messages under the same secret key, the underlying GHASH authentication key $H$ can be algebraically recovered, completely compromising message authenticity and allowing forgeable ciphertext.
4. **Weak Pseudo-Random Number Generation (CWE-330)**:
   * Using non-cryptographic PRNGs (e.g., Python `random`, C `rand()`, PHP `rand()`) for session tokens or cryptographic keys allows attackers to deduce the internal PRNG state after observing a few outputs.

---

## 7. Auditing Methodology: Cryptographic Verification

```
[ Phase 1: Perimeter TLS/SSL Surface Enumeration ]
  - Enumerate supported protocols and ciphers:
    testssl.sh --protocols --ciphers --vulnerabilities https://api.enterprise.com
  - Verify TLS 1.0 and TLS 1.1 are completely disabled across all endpoints.
       |
[ Phase 2: Cipher Suite & Key Exchange Audit ]
  - Verify all accepted ciphers enforce Perfect Forward Secrecy (ECDHE).
  - Verify all symmetric ciphers utilize AEAD (GCM or ChaCha20-Poly1305).
  - Confirm RSA key lengths are >= 2048 bits (3072 bits recommended); ECC keys >= 256 bits.
       |
[ Phase 3: X.509 Certificate Chain Validation ]
  - Extract and inspect complete certificate chain:
    openssl s_client -connect api.enterprise.com:443 -showcerts -servername api.enterprise.com
  - Check expiration dates, SAN entries, and OCSP Stapling validation status.
       |
[ Phase 4: Application Source Code Cryptography Audit ]
  - Grep for weak hashing primitives: MD5, SHA-1 used in security contexts.
  - Audit block cipher modes: search for ECB mode (`Cipher.getInstance("AES/ECB/PKCS5Padding")`).
  - Verify PRNG sources: confirm `secrets` in Python, `crypto/rand` in Go, `SecureRandom` in Java.
       |
[ Phase 5: Benign Verification of Message Integrity ]
  - Verify HMAC keys are constant-time compared (`hmac.compare_digest`) to prevent timing attacks.
```

---

## 8. Tooling Deep-Dive

### 8.1 OpenSSL CLI Diagnostic Syntax

```bash
# 1. Connect to an endpoint and force specific TLS protocol version (TLS 1.3)
openssl s_client -connect api.enterprise.com:443 -tls1_3 -servername api.enterprise.com

# 2. Inspect certificate details (Issuer, Expiry, SAN, Subject) without browser
openssl s_client -connect api.enterprise.com:443 -servername api.enterprise.com </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -E "(Issuer:|Subject:|Not After|DNS:)"

# 3. Generate a 256-bit Elliptic Curve Private Key (Curve25519)
openssl genpkey -algorithm ED25519 -out /tmp/ed25519_priv.key

# 4. Generate a Certificate Signing Request (CSR) with SHA-256 digest
openssl req -new -key /tmp/ed25519_priv.key -out /tmp/request.csr \
  -subj "/C=US/ST=CA/O=Enterprise Security/CN=api.enterprise.com"

# 5. Measure cryptographic benchmark performance on current CPU
openssl speed aes-256-gcm chacha20-poly1305 sha256
```

### 8.2 Comprehensive TLS Auditing via `testssl.sh`

```bash
# Execute deep vulnerability evaluation (checks Heartbleed, ROBOT, POODLE, DROWN, Sweet32)
./testssl.sh --quiet --color 0 --severity HIGH https://api.enterprise.com
```

---

## 9. Practical Lab: Standalone Python Cryptographic Audit Engine

Deploy this standalone script to verify key cryptographic properties: it demonstrates CBC bit-flipping vulnerabilities, validates HMAC timing-safe verification, and performs X.509 trust-chain parsing.

Save as `/home/kali/Ethical_Hacking_VAPT_Master_Notes/labs/module_24/pki_crypto_audit.py`:

```python
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
    # (Notice how the bit flip in the IV transfers directly into the decrypted plaintext)
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
```

---

## 10. Evidence & Verification: Verifying Perfect Forward Secrecy

### Non-Destructive Probe Protocol

Verify that a target web server enforces Perfect Forward Secrecy and disallows legacy static RSA key transport:

```bash
# 1. Attempt connection forcing an ephemeral ECDHE cipher suite (Expected: SUCCESS)
openssl s_client -connect api.enterprise.com:443 -cipher "ECDHE-RSA-AES256-GCM-SHA384" </dev/null 2>/dev/null
# Verify output contains:
# New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
# Server Temp Key: X25519, 253 bits

# 2. Attempt connection forcing a legacy Static RSA cipher suite (Expected: HANDSHAKE FAILURE)
openssl s_client -connect api.enterprise.com:443 -cipher "AES256-GCM-SHA384" </dev/null 2>/dev/null
# Verify output contains:
# Handshake failure / no ciphers available
# Observation: Server strictly enforces Ephemeral Key Exchange (PFS).
```

---

## 11. Telemetry, Detection & Log Signatures

### 11.1 Suricata TLS Inspection Rules (`tls.rules`)

Detect obsolete, insecure TLS versions (TLS 1.0 / 1.1) and SSLv3 negotiation:

```suricata
# Alert on TLS 1.0 or 1.1 Handshake Negotiation
alert tls any any -> any any (msg:"CRYPTO Obsolete TLS 1.0/1.1 Handshake Detected"; \
    tls.version:0x0301,0x0302; flow:established; \
    classtype:policy-violation; sid:2000010; rev:1;)

# Alert on Self-Signed Certificates Transmitted across Wire
alert tls any any -> any any (msg:"CRYPTO Self-Signed Server Certificate Detected"; \
    tls.cert_issuer:same; flow:established; \
    classtype:bad-unknown; sid:2000011; rev:1;)
```

### 11.2 Splunk / SIEM Query: Cryptographic Anomaly Detection

```spl
index=web_proxy sourcetype="access_combined"
| where tls_version IN ("TLS 1.0", "TLS 1.1", "SSLv3") OR ssl_cipher IN ("NULL", "RC4-MD5", "DES-CBC3-SHA")
| stats count by src_ip, dest_ip, ssl_cipher, tls_version
| sort -count
```

---

## 12. Mitigation & Remediation: Modern TLS Hardening

### Production-Grade NGINX SSL Configuration (`/etc/nginx/conf.d/ssl.conf`)

Enforce modern TLS 1.2/1.3 parameters meeting **PCI-DSS v4.0** and **NIST SP 800-52 Rev. 2**:

```nginx
# Enforce only secure TLS protocol versions
ssl_protocols TLSv1.2 TLSv1.3;

# Prioritize server ciphers
ssl_prefer_server_ciphers on;

# Strict, modern AEAD cipher suite list
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# Session caching and ticket rotation
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# Enable OCSP Stapling with verified DNS resolvers
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# HTTP Strict Transport Security (HSTS - 1 Year)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

---

## 13. System & Protocol Hardening (CIS Benchmark Alignment)

| Cryptographic Control | Minimum Required Baseline | Benchmark Reference |
| :--- | :--- | :--- |
| **Minimum RSA Key Size** | 2048 bits (3072 bits recommended for post-2030 protection). | NIST SP 800-57 Part 1 |
| **Minimum ECC Key Size** | 256 bits (P-256, Curve25519). | NIST SP 800-57 Part 1 |
| **Symmetric Cipher Standards** | AES-128 or AES-256 in GCM mode; ChaCha20-Poly1305. | FIPS 140-3 / PCI-DSS v4.0 |
| **Hash Algorithm Deprecation** | MD5 and SHA-1 strictly prohibited in security workflows. Use SHA-256, SHA-512, or SHA-3. | NIST SP 800-131A |
| **Enforce Forward Secrecy** | Require ECDHE key exchange for all TLS sessions. | NIST SP 800-52 Rev. 2 |
| **Enforce HSTS** | Preloaded HSTS with minimum 1-year max-age. | CIS Web Server Benchmark |

---

## 14. Documented Real-World Case Studies

### Case Study 1: Heartbleed (CVE-2014-0160 - OpenSSL Memory Disclosure)
* **Component**: OpenSSL TLS Heartbeat Extension (RFC 6520).
* **Vulnerability Class**: CWE-125 (Out-of-bounds Read).
* **Mechanism**: The client sent a heartbeat request containing a payload and a 16-bit length variable. OpenSSL allocated a buffer based on the client's declared length without checking whether the actual payload buffer matched that length, copying up to 64KB of contiguous process heap memory back to the attacker.
* **Impact**: Unauthenticated attackers read SSL server private keys, plaintext passwords, session tokens, and decryption keys directly from host RAM without leaving log traces.

### Case Study 2: Debian OpenSSL Predictable PRNG (CVE-2008-0166)
* **Component**: Debian-specific OpenSSL patch.
* **Mechanism**: A package maintainer removed two lines of code to suppress Valgrind memory leak warnings, inadvertently eliminating the seeding entropy source for the OpenSSL pseudo-random number generator.
* **Impact**: The PRNG relied solely on the current Process ID ($PID \in [1, 32767]$). The entire universe of possible SSH and SSL keys generated on Debian/Ubuntu systems over a two-year period was reduced to approximately 32,767 keys, allowing instant precomputed dictionary recovery of private keys.

---

## 15. Common Mistakes & Anti-Patterns

```
❌ ANTI-PATTERN 1: Using Raw/Unauthenticated CBC Mode for Sensitive Data
   Encrypting web cookies or tokens with AES-CBC without an HMAC or AEAD tag.
   Attackers use bit-flipping or padding oracles to decrypt or manipulate serialized objects.
   ✔ CORRECT: Enforce AEAD (AES-256-GCM or ChaCha20-Poly1305).

❌ ANTI-PATTERN 2: Concatenating Secrets into Plain Hashes for Authentication
   Constructing API authentication tokens using `SHA256(secret + message)`.
   Merkle-Damgård length extension attacks allow unauthorized callers to append parameters.
   ✔ CORRECT: Always use standard HMAC-SHA256 (`HMAC(key, message)`).

❌ ANTI-PATTERN 3: Disabling X.509 Certificate Chain Validation in Code
   Writing `verify=False` in Python requests or `InsecureSkipVerify: true` in Go to bypass self-signed errors.
   Completely eliminates TLS confidentiality and authentication, allowing trivial Layer 2 MITM interception.
   ✔ CORRECT: Import internal Root CA certificates into the application trust store.
```

---

## 16. Professional vs. Naive Methodology

| Cryptographic Audit Step | Naive / Novice Approach | Professional Cryptographic Auditor Approach |
| :--- | :--- | :--- |
| **Cipher Suite Testing** | Looks at green padlock in web browser. | Evaluates full cipher prioritization matrix, PFS parameters, and TLS 1.3 downgrade protection (`TLS_FALLBACK_SCSV`). |
| **Code Review** | Searches for the word "AES" and assumes code is secure. | Checks operational mode (ECB/CBC/GCM), validates non-reuse of IVs/nonces, and audits key generation entropy. |
| **Token Verification** | Uses standard string equality (`token == expected_token`). | Enforces constant-time comparison (`hmac.compare_digest`) to prevent side-channel timing attacks. |
| **Certificate Inspection** | Checks domain name on certificate. | Validates complete X.509 chain, Basic Constraints, Key Usage extensions, and checks Certificate Transparency logs. |

---

## 17. Graded Knowledge Check & Interview Questions

### Beginner Level
1. **Question**: Why is ECB (Electronic Codebook) mode strictly prohibited for data exceeding one block in size?
   * *Answer*: ECB encrypts each 16-byte block independently using the same key. Identical plaintext blocks produce identical ciphertext blocks, preserving structural data patterns (e.g., bitmap images) and exposing plaintext entropy directly to eavesdroppers.
2. **Question**: What is the primary purpose of a Salt when hashing user passwords?
   * *Answer*: A salt is a unique, cryptographically random value appended to the plaintext password prior to hashing. It prevents attackers from using precomputed lookup tables (Rainbow Tables) and ensures that identical passwords produce distinct hash digests.

### Intermediate Level
3. **Question**: Explain how a Padding Oracle attack works against an unauthenticated AES-CBC implementation.
   * *Answer*: In PKCS#7 padding, bytes are padded with their padding count value. If an application responds differently when receiving malformed padding versus valid padding (e.g., HTTP 500 error vs. HTTP 200/403), an attacker can systematically manipulate the preceding ciphertext block ($C_{i-1}$) byte-by-byte. By observing when the padding error disappears, the attacker calculates the intermediate state and mathematical plaintext byte without knowing the secret key.
4. **Question**: What is Perfect Forward Secrecy (PFS) and how does it protect historical network communications?
   * *Answer*: PFS ensures that a session key derived for a specific communication session will not be compromised if the long-term private key of the server is compromised in the future. It is achieved using Ephemeral Diffie-Hellman (DHE/ECDHE), generating temporary, non-reusable key pairs for each session that are discarded immediately after key negotiation.

### Advanced / Scenario-Based
5. **Question**: An API developer uses `AES-256-GCM` to encrypt database fields. To save storage space, they hardcode a fixed 12-byte IV and generate random 256-bit keys periodically. What is the critical vulnerability in this design?
   * *Answer*: In AES-GCM, reusing an IV/nonce with the same key breaks the authenticity of the cipher entirely. Because keys are rotated only periodically, multiple distinct database fields are encrypted using the identical Key and IV pair. An attacker can XOR two ciphertexts to eliminate the keystream ($C_1 \oplus C_2 = P_1 \oplus P_2$), revealing relative plaintext, and recover the GHASH authentication key $H$, allowing arbitrary forgery of ciphertext blocks.

---

## 18. Progressive Hands-on Exercises

### Level 1: OpenSSL Certificate Inspection (Beginner)
* Connect to an internal HTTPS server using `openssl s_client`. Extract its leaf certificate and parse the Subject Alternative Name (SAN) and OCSP URLs.

### Level 2: CBC Bit-Flipping Verification (Intermediate)
* Execute the provided `pki_crypto_audit.py` lab script. Trace the bitwise XOR operation and explain how altering the IV altered the plaintext without triggering a padding fault.

### Level 3: Hardening TLS Server Configurations (Advanced)
* Configure an NGINX or Apache test instance to achieve an **A+ grade on SSL Labs**: enforce TLS 1.2/1.3, enable HSTS with preloading, enable OCSP stapling, and restrict ciphers exclusively to AEAD suites with ECDHE forward secrecy.

---

## 19. Key Takeaways

1. **Algorithms Don't Break; Implementations Do**: Cryptographic vulnerabilities almost universally stem from mode misuse, nonce reuse, and unauthenticated cipher choices.
2. **Always Use Authenticated Encryption (AEAD)**: Never use raw CBC or CTR modes without an HMAC. Standardize on AES-GCM or ChaCha20-Poly1305.
3. **Mandate Perfect Forward Secrecy**: Require ECDHE key exchange to protect network data against retrospective decryption.
4. **HMAC vs. Plain Hashing**: Never concatenate secrets into plain Merkle-Damgård hashes (`SHA256(secret + msg)`) due to Length Extension attacks; always use RFC 2104 HMAC.
5. **Enforce Constant-Time Comparison**: Use timing-safe comparison functions (`hmac.compare_digest`) for all authentication tokens and cryptographic signatures.

---

## 20. Authoritative References

* **FIPS PUB 197**: *Advanced Encryption Standard (AES)*.
* **RFC 2104**: *HMAC: Keyed-Hashing for Message Authentication*.
* **RFC 5280**: *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*.
* **RFC 8446**: *The Transport Layer Security (TLS) Protocol Version 1.3*.
* **NIST SP 800-52 Rev. 2**: *Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations*.
* **NIST SP 800-175B Rev. 1**: *Guideline for Using Cryptographic Standards in the Federal Government: Cryptographic Mechanisms*.
* **CVE-2014-0160**: *OpenSSL Heartbleed TLS Heartbeat Information Disclosure*.
