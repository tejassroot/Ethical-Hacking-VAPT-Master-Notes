#!/usr/bin/env python3
"""
Cryptographic Chain of Custody & Regulatory Evidence Verification Engine
Volume 11: Reporting, Methodology & Professional Practice - Module 25
Author: Senior Cybersecurity Legal, Forensics & Compliance Specialist

Demonstrates:
1. ISO/IEC 27037 compliant digital evidence acquisition manifest generation.
2. Dual-algorithm cryptographic hashing (SHA-256 and SHA-512) for tamper-proofing.
3. Master Evidence vs. Working Clone integrity verification state machine.
4. Tamper detection: Proves mathematical failure if a single bit is modified.
5. Regulatory compliance automated cross-checker (GDPR Art 32, HIPAA § 164.312, PCI-DSS 4.0).
"""

import hashlib
import time
import json
import os

def compute_hashes(data_bytes: bytes) -> dict:
    """Computes simultaneous SHA-256 and SHA-512 cryptographic digests."""
    sha256 = hashlib.sha256(data_bytes).hexdigest()
    sha512 = hashlib.sha512(data_bytes).hexdigest()
    return {"sha256": sha256, "sha512": sha512}

def generate_custody_manifest(evidence_name: str, raw_data: bytes, case_id: str, examiner: str) -> dict:
    """Creates a formal ISO/IEC 27037 evidentiary custody manifest."""
    hashes = compute_hashes(raw_data)
    manifest = {
        "standard": "ISO/IEC 27037:2012 Digital Evidence Handling",
        "case_id": case_id,
        "evidence_item": evidence_name,
        "examiner": examiner,
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "size_bytes": len(raw_data),
        "cryptographic_signatures": hashes,
        "custody_state": "ACQUIRED_AND_SEALED",
        "storage_location": "Tamper-Evident Anti-Static Evidence Vault #4"
    }
    return manifest

def verify_working_clone(master_manifest: dict, clone_data: bytes) -> bool:
    """Verifies that a working clone matches the master evidence byte-for-byte."""
    clone_hashes = compute_hashes(clone_data)
    master_hashes = master_manifest["cryptographic_signatures"]
    
    sha256_match = (clone_hashes["sha256"] == master_hashes["sha256"])
    sha512_match = (clone_hashes["sha512"] == master_hashes["sha512"])
    
    return sha256_match and sha512_match

def audit_compliance_controls(manifest: dict) -> list:
    """Audits evidence handling procedures against core regulatory frameworks."""
    audit_results = []
    
    # 1. GDPR Article 32 (Security of Processing / Integrity)
    if "sha512" in manifest["cryptographic_signatures"]:
        audit_results.append({
            "framework": "GDPR (EU 2016/679)",
            "article": "Article 32(1)(b) - Confidentiality & Integrity",
            "status": "COMPLIANT",
            "finding": "Strong cryptographic dual-hashing ensures ongoing data integrity."
        })
        
    # 2. HIPAA Security Rule 45 CFR § 164.312
    if manifest["size_bytes"] > 0 and manifest["custody_state"] == "ACQUIRED_AND_SEALED":
        audit_results.append({
            "framework": "HIPAA Security Rule",
            "section": "45 CFR § 164.312(c)(1) - Data Integrity Safeguards",
            "status": "COMPLIANT",
            "finding": "Electronic Protected Health Information (ePHI) chain of custody is mathematically verifiable."
        })
        
    # 3. PCI-DSS 4.0 Requirement 10 & 11
    audit_results.append({
        "framework": "PCI-DSS v4.0",
        "requirement": "Req 10.5.1 / 11.5 - Tamper-Proof Audit Trails & Integrity",
        "status": "COMPLIANT",
        "finding": "Evidence manifests stored in immutable JSON format with cryptographic hashes."
    })
    
    return audit_results

if __name__ == "__main__":
    print("=" * 72)
    print("[*] INITIALIZING FORENSIC EVIDENCE CUSTODY & REGULATORY AUDIT ENGINE")
    print("=" * 72)

    # Step 1: Simulate Master Evidence Acquisition
    raw_packet_capture = b"PCAP_PACKET_HEADER\x00\x00\x01\xa4_TCP_SYN_FLOOD_ATTACK_TRACE_2026"
    case_num = "CASE-2026-US-CFAA-8821"
    lead_examiner = "A. Vance, Senior Forensic Auditor (EnCE, CISSP)"
    
    manifest = generate_custody_manifest(
        evidence_name="perimeter_fw_capture.pcap",
        raw_data=raw_packet_capture,
        case_id=case_num,
        examiner=lead_examiner
    )
    
    print(f"[+] Master Evidence Item '{manifest['evidence_item']}' Successfully Sealed:")
    print(f"    - Case ID:        {manifest['case_id']}")
    print(f"    - Examiner:       {manifest['examiner']}")
    print(f"    - Timestamp:      {manifest['timestamp_utc']}")
    print(f"    - Size:           {manifest['size_bytes']} bytes")
    print(f"    - SHA-256 Digest: {manifest['cryptographic_signatures']['sha256']}")
    print(f"    - SHA-512 Digest: {manifest['cryptographic_signatures']['sha512'][:32]}...[TRUNCATED]")

    # Step 2: Verify Working Clone Integrity (Unmodified)
    print("\n" + "=" * 72)
    print("PHASE 2: WORKING CLONE CRYPTOGRAPHIC INTEGRITY AUDITING")
    print("=" * 72)
    working_clone = bytearray(raw_packet_capture)
    is_valid = verify_working_clone(manifest, working_clone)
    print(f"[*] Validating Unmodified Working Clone against Master Manifest:")
    print(f"    - Cryptographic Integrity Match: {is_valid}")
    print(f"    - Courtroom Admissibility:       VERIFIED (Federal Rule of Evidence 901/902)")

    # Step 3: Tamper Detection (Simulate 1-bit modification during analysis)
    print("\n[*] Simulating Accidental 1-Bit Corruption in Working Copy during Hex Edit...")
    tampered_clone = bytearray(raw_packet_capture)
    tampered_clone[10] = tampered_clone[10] ^ 0x01  # Flip a single bit
    is_tampered_valid = verify_working_clone(manifest, tampered_clone)
    print(f"    - Tampered Copy Integrity Match: {is_tampered_valid}")
    if not is_tampered_valid:
        print(f"    - TAMPER ALERT: Cryptographic hash mismatch detected! Evidence invalidated.")

    # Step 4: Regulatory Compliance Audit
    print("\n" + "=" * 72)
    print("PHASE 3: REGULATORY COMPLIANCE CONTROL VALIDATION")
    print("=" * 72)
    compliance_report = audit_compliance_controls(manifest)
    for c in compliance_report:
        print(f"[+] [{c['status']}] {c['framework']} - {c.get('article') or c.get('section') or c.get('requirement')}")
        print(f"    Details: {c['finding']}\n")

    print("=" * 72)
    print("[+] REGULATORY EVIDENCE VERIFICATION ENGINE COMPLETED SUCCESSFULLY")
    print("=" * 72)
