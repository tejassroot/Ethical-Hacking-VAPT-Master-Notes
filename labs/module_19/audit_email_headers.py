#!/usr/bin/env python3
"""
Automated RFC 5322 Email Header Forensics & Anomaly Detection Engine
Audits hop chronology, verifies connecting IP authenticity, and flags spoofing artifacts.
"""

import sys
import os
import re
from email import policy
from email.parser import BytesParser
from datetime import datetime
import ipaddress

def parse_received_hop(hop_str):
    """Extracts from, by, IP, protocol, and timestamp from Received header."""
    hop_data = {
        "raw": hop_str,
        "from_claimed": "Unknown",
        "from_ip": "Unknown",
        "by": "Unknown",
        "with": "Unknown",
        "timestamp_raw": "Unknown",
        "dt": None
    }
    
    # Extract 'from' clause
    m_from = re.search(r'from\s+([^\s]+)', hop_str, re.IGNORECASE)
    if m_from:
        hop_data["from_claimed"] = m_from.group(1)
        
    # Extract IP address inside brackets
    m_ip = re.search(r'\[([0-9a-fA-F\.:]+)\]', hop_str)
    if m_ip:
        candidate_ip = m_ip.group(1)
        try:
            ipaddress.ip_address(candidate_ip)
            hop_data["from_ip"] = candidate_ip
        except ValueError:
            pass

    # Extract 'by' clause
    m_by = re.search(r'by\s+([^\s]+)', hop_str, re.IGNORECASE)
    if m_by:
        hop_data["by"] = m_by.group(1)

    # Extract 'with' protocol
    m_with = re.search(r'with\s+([^\s;]+)', hop_str, re.IGNORECASE)
    if m_with:
        hop_data["with"] = m_with.group(1)

    # Extract trailing timestamp after semicolon
    if ';' in hop_str:
        ts_part = hop_str.split(';')[-1].strip()
        ts_clean = re.sub(r'\(.*?\)', '', ts_part).strip()
        hop_data["timestamp_raw"] = ts_clean
        
        for fmt in (
            "%a, %d %b %Y %H:%M:%S %z",
            "%d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S",
        ):
            try:
                hop_data["dt"] = datetime.strptime(ts_clean, fmt)
                break
            except ValueError:
                continue

    return hop_data

def audit_eml(filepath):
    print("=" * 80)
    print(f"[*] Analyzing Email Forensic Artifact: {filepath}")
    print("=" * 80)
    
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Identity & Message Alignment
    from_hdr = str(msg.get("From", ""))
    return_path = str(msg.get("Return-Path", ""))
    reply_to = str(msg.get("Reply-To", ""))
    msg_id = str(msg.get("Message-ID", ""))
    subject = str(msg.get("Subject", ""))
    auth_results = str(msg.get("Authentication-Results", ""))
    
    print(f"Subject:        {subject}")
    print(f"RFC5322 From:   {from_hdr}")
    print(f"Return-Path:    {return_path}")
    print(f"Reply-To:       {reply_to if reply_to else '[None specified]'}")
    print(f"Message-ID:     {msg_id}")
    print("-" * 80)

    # 2. Check for Alignment Gaps
    anomalies = []
    if return_path and from_hdr:
        rp_dom = re.search(r'@([\w\.-]+)', return_path)
        from_dom = re.search(r'@([\w\.-]+)', from_hdr)
        if rp_dom and from_dom and rp_dom.group(1).lower() != from_dom.group(1).lower():
            anomalies.append(f"[!] ENVELOPE MISALIGNMENT: Return-Path domain '{rp_dom.group(1)}' != From domain '{from_dom.group(1)}'")

    # 3. Process Received Hop Chain
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        print("[!] CRITICAL: No 'Received:' headers found! Artifact may be truncated.")
        return

    print(f"[*] Total Transmission Hops Detected: {len(received_headers)}")
    hops = [parse_received_hop(h) for h in received_headers]
    
    # Chronological order is bottom-to-top
    chrono_hops = list(reversed(hops))
    
    print("\n--- CHRONOLOGICAL HOP ANALYSIS (Origin -> Destination) ---")
    prev_dt = None
    for idx, hop in enumerate(chrono_hops, 1):
        print(f"\n[Hop #{idx}]")
        print(f"  Claimed From: {hop['from_claimed']} [{hop['from_ip']}]")
        print(f"  Received By:  {hop['by']}")
        print(f"  Protocol:     {hop['with']}")
        print(f"  Timestamp:    {hop['timestamp_raw']}")
        
        if hop["dt"]:
            if prev_dt:
                delta_sec = (hop["dt"] - prev_dt).total_seconds()
                print(f"  Hop Delay:    {delta_sec:.1f} seconds")
                if delta_sec < -60:
                    anomalies.append(f"[!] TIMESTAMP REGRESSION: Hop #{idx} timestamp precedes Hop #{idx-1} by {abs(delta_sec)}s")
                elif delta_sec > 86400:
                    anomalies.append(f"[!] UNUSUAL LATENCY: Hop #{idx} took >24 hours ({delta_sec}s) to forward.")
            prev_dt = hop["dt"]
            
    # Authoritative Edge Hop: The topmost Received header (index 0 of original headers)
    edge_hop = hops[0]
    print("\n" + "=" * 80)
    print(f"[*] AUTHORITATIVE EDGE INGESTION HOP:")
    print(f"    Gateway Host: {edge_hop['by']}")
    print(f"    Socket IP:    {edge_hop['from_ip']}")
    print("=" * 80)

    # 4. Authentication-Results Triage
    if auth_results:
        print("\n[*] Authentication-Results Analysis:")
        print(f"    Raw: {auth_results[:120]}...")
        if "spf=pass" in auth_results.lower():
            print("    [+] SPF: PASS")
        elif "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
            anomalies.append("[!] AUTH FAIL: SPF verification failed at receiving gateway.")
            print("    [-] SPF: FAIL/SOFTFAIL")
            
        if "dkim=pass" in auth_results.lower():
            print("    [+] DKIM: PASS")
        elif "dkim=fail" in auth_results.lower():
            anomalies.append("[!] AUTH FAIL: DKIM cryptographic signature verification failed.")
            print("    [-] DKIM: FAIL")

        if "dmarc=pass" in auth_results.lower():
            print("    [+] DMARC: PASS")
        elif "dmarc=fail" in auth_results.lower():
            anomalies.append("[!] DMARC POLICY BREACH: DMARC failed identifier alignment.")
            print("    [-] DMARC: FAIL")

    # 5. Summary Findings
    print("\n" + "=" * 80)
    print("[*] AUDIT FINDINGS SUMMARY:")
    if anomalies:
        for a in anomalies:
            print(f"  {a}")
    else:
        print("  [+] No major structural anomalies detected. All hops and records align.")
    print("=" * 80 + "\n")

SAMPLE_SYNTHETIC_EML = b"""Delivered-To: recipient@corp.test
Received: by 2002:a05:6512:1234 with SMTP id abc;
        Fri, 05 Sep 2026 14:02:00 +0000
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@corp.test designates 198.51.100.10 as permitted sender) smtp.mailfrom=sender@corp.test;
       dkim=pass header.i=@corp.test header.s=2026mail;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corp.test
Received: from mail.corp.test ([198.51.100.10])
        by mx.google.com with ESMTP id xyz;
        Fri, 05 Sep 2026 14:01:50 +0000
From: "Security Team" <sender@corp.test>
To: recipient@corp.test
Subject: Security Verification Notice
Date: Fri, 05 Sep 2026 14:01:45 +0000
Message-ID: <test-12345@corp.test>

This is a synthetic test email.
"""

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        audit_eml(sys.argv[1])
    else:
        print("[*] No EML file provided. Running automated synthetic email forensics audit...")
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(SAMPLE_SYNTHETIC_EML)
            tmp_path = tmp.name
        try:
            audit_eml(tmp_path)
            print("[+] Synthetic email forensics audit completed successfully.")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

