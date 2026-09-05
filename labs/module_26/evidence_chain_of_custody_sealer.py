#!/usr/bin/env python3
"""
================================================================================
MODULE 26 LAB: EVIDENCE CHAIN-OF-CUSTODY & CRYPTOGRAPHIC SEALER
PURPOSE: Implements ISO/IEC 27037 and NIST SP 800-115 digital evidence integrity,
         computing SHA-256 digests, UTC timestamps, and tamper verification.
COMPLIANCE: Authorized auditing methodology / Forensic evidence preservation.
================================================================================
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone

def compute_sha256(filepath):
    """Computes streaming SHA-256 digest of a target file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def seal_evidence_directory(target_dir):
    """Generates an immutable cryptographic manifest of all files in the directory."""
    print("=" * 72)
    print(f"[*] SEALING EVIDENCE DIRECTORY: {target_dir}")
    print("=" * 72)

    manifest_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "standard": "ISO/IEC 27037:2012 / NIST SP 800-115",
        "artifacts": []
    }

    manifest_filename = "evidence_manifest.json"

    for root, _, files in os.walk(target_dir):
        for fname in sorted(files):
            if fname == manifest_filename or fname.endswith(".manifest.txt"):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, target_dir)
            size_bytes = os.path.getsize(full_path)
            digest = compute_sha256(full_path)

            manifest_data["artifacts"].append({
                "relative_path": rel_path,
                "size_bytes": size_bytes,
                "sha256_digest": digest
            })
            print(f"[+] Sealed: {rel_path:35s} | Size: {size_bytes:6d} B | Digest: {digest[:16]}...[MASKED]")

    manifest_path = os.path.join(target_dir, manifest_filename)
    with open(manifest_path, 'w') as mf:
        json.dump(manifest_data, mf, indent=2)

    print(f"\n[+] Sealed {len(manifest_data['artifacts'])} artifacts.")
    print(f"[+] Evidence manifest written to: {manifest_path}")
    return manifest_path

def verify_evidence_manifest(target_dir):
    """Verifies all directory files against the sealed manifest to detect tampering."""
    print("\n" + "=" * 72)
    print(f"[*] VERIFYING EVIDENCE INTEGRITY: {target_dir}")
    print("=" * 72)

    manifest_path = os.path.join(target_dir, "evidence_manifest.json")
    if not os.path.exists(manifest_path):
        print("[-] Manifest not found! Directory is unsealed.")
        return False

    with open(manifest_path, 'r') as mf:
        manifest = json.load(mf)

    all_intact = True
    for item in manifest["artifacts"]:
        fpath = os.path.join(target_dir, item["relative_path"])
        if not os.path.exists(fpath):
            print(f"[!] CRITICAL: Missing artifact: {item['relative_path']}")
            all_intact = False
            continue

        current_digest = compute_sha256(fpath)
        if current_digest == item["sha256_digest"]:
            print(f"[+] VERIFIED: {item['relative_path']:35s} | SHA-256 matches sealed record.")
        else:
            print(f"[!] TAMPER DETECTED: {item['relative_path']:35s} | Checksum mismatch!")
            all_intact = False

    return all_intact

def run_self_test():
    """Generates synthetic test artifacts, seals them, verifies, and tests tamper detection."""
    test_dir = "/tmp/vapt_evidence_test"
    os.makedirs(test_dir, exist_ok=True)

    # 1. Create mock assessment artifacts
    with open(os.path.join(test_dir, "nmap_syn_scan.log"), "w") as f:
        f.write("Nmap 7.94 scan initiated 2026-09-05 10:00:00 UTC\nHost: 10.10.10.5 Port 445/tcp OPEN\n")

    with open(os.path.join(test_dir, "smb_negotiation.pcap"), "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    # 2. Seal directory
    seal_evidence_directory(test_dir)

    # 3. Verify clean state
    intact = verify_evidence_manifest(test_dir)
    assert intact, "Evidence integrity check failed on clean directory!"

    # 4. Simulate tampering
    with open(os.path.join(test_dir, "nmap_syn_scan.log"), "a") as f:
        f.write("Unauthorized modification appended to log.\n")

    print("\n[*] Simulating unauthorized modification to nmap_syn_scan.log...")
    tamper_result = verify_evidence_manifest(test_dir)
    assert not tamper_result, "Expected tamper detection to catch modified file!"
    print("[+] Tamper detection engine successfully caught unauthorized alteration!")

    # Clean up test artifacts
    for f in os.listdir(test_dir):
        os.remove(os.path.join(test_dir, f))
    os.rmdir(test_dir)
    print("\n[+] Chain of custody self-test passed successfully.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--test":
        target = sys.argv[1]
        seal_evidence_directory(target)
        verify_evidence_manifest(target)
    else:
        run_self_test()
