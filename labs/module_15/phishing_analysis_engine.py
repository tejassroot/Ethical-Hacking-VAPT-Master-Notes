#!/usr/bin/env python3
"""
Phishing Architecture & Email Security Analysis Engine
Standalone diagnostic tool for evaluating DMARC policies, recursive SPF DNS
lookup trees (RFC 7208 10-lookup limit), identifier alignment, and AiTM proxy headers.
"""

import sys
import os
import re
from typing import Dict, List, Tuple, Optional

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive values to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def evaluate_dmarc_record(record_str: str) -> Dict[str, any]:
    """
    Parses an RFC 7489 DMARC TXT record string into structured policy tags,
    evaluating defensive enforcement posture and spoofing risk.
    """
    tags = {}
    tokens = [t.strip() for t in record_str.split(';') if t.strip()]
    for token in tokens:
        if '=' in token:
            k, v = token.split('=', 1)
            tags[k.strip().lower()] = v.strip().lower()

    version = tags.get('v', '')
    if version != 'dmarc1':
        return {"Error": "INVALID_DMARC_VERSION", "Raw": record_str, "Risk_Level": "CRITICAL"}

    policy = tags.get('p', 'none')
    subdomain_policy = tags.get('sp', policy)
    percentage = int(tags.get('pct', '100'))
    aspf = tags.get('aspf', 'r')   # 'r' = relaxed, 's' = strict
    adkim = tags.get('adkim', 'r') # 'r' = relaxed, 's' = strict
    rua = tags.get('rua', '')

    is_enforced = (policy == 'reject') and (percentage == 100)
    
    if policy == 'reject' and percentage == 100 and subdomain_policy == 'reject':
        risk = "LOW (Hardened - Full Impersonation Drop)"
    elif policy == 'quarantine' or percentage < 100:
        risk = "MEDIUM (Quarantine or Partial Enforcement)"
    else:
        risk = "HIGH (Monitoring Mode - Unprotected against Impersonation)"

    return {
        "Version": version,
        "Policy": policy,
        "Subdomain_Policy": subdomain_policy,
        "Percentage": percentage,
        "SPF_Alignment_Mode": "STRICT" if aspf == 's' else "RELAXED",
        "DKIM_Alignment_Mode": "STRICT" if adkim == 's' else "RELAXED",
        "Reporting_Configured": bool(rua),
        "Is_Fully_Enforced": is_enforced,
        "Risk_Assessment": risk
    }

def calculate_recursive_spf_lookups(domain: str, mock_dns_db: Dict[str, str], visited: Optional[set] = None) -> Tuple[int, List[str], bool]:
    """
    Traverses SPF records recursively (resolving include: mechanisms) to calculate
    the exact RFC 7208 10-DNS-lookup limit. Returns (count, visited_domains, is_permerror).
    """
    if visited is None:
        visited = set()

    if domain in visited:
        # Loop detected
        return 0, list(visited), True

    visited.add(domain)
    raw_record = mock_dns_db.get(domain, "")
    if not raw_record.startswith("v=spf1"):
        return 0, list(visited), False

    dns_mechanisms = ('include', 'a', 'mx', 'ptr', 'exists', 'redirect')
    tokens = raw_record.split()
    total_lookups = 0
    is_permerror = False

    for token in tokens[1:]:  # Skip 'v=spf1'
        mechanism = token.split(':')[0].lower() if ':' in token else token.lower()
        # Strip qualifier (+, -, ~, ?)
        if mechanism.startswith(('+', '-', '~', '?')):
            clean_mech = mechanism[1:]
        else:
            clean_mech = mechanism

        if clean_mech in dns_mechanisms:
            total_lookups += 1
            if clean_mech == 'include' and ':' in token:
                subdomain = token.split(':', 1)[1]
                sub_count, _, sub_perm = calculate_recursive_spf_lookups(subdomain, mock_dns_db, visited)
                total_lookups += sub_count
                if sub_perm:
                    is_permerror = True

    if total_lookups > 10:
        is_permerror = True

    return total_lookups, list(visited), is_permerror

def evaluate_identifier_alignment(header_from: str, mail_from: str, dkim_domain: str, aspf_mode: str = "r", adkim_mode: str = "r") -> Dict[str, any]:
    """
    Evaluates DMARC Identifier Alignment between the RFC 5322 From: header domain
    and the authenticated SPF / DKIM domains under Strict vs. Relaxed rules.
    """
    def get_base_domain(d: str) -> str:
        parts = d.lower().split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else d.lower()

    header_domain = header_from.split('@')[-1].lower()
    mail_domain = mail_from.split('@')[-1].lower()
    dkim_d = dkim_domain.lower()

    # SPF Alignment
    if aspf_mode == "s":
        spf_aligned = (header_domain == mail_domain)
    else:
        spf_aligned = (get_base_domain(header_domain) == get_base_domain(mail_domain))

    # DKIM Alignment
    if adkim_mode == "s":
        dkim_aligned = (header_domain == dkim_d)
    else:
        dkim_aligned = (get_base_domain(header_domain) == get_base_domain(dkim_d))

    dmarc_pass = spf_aligned or dkim_aligned

    return {
        "Header_From_Domain": header_domain,
        "SPF_Envelope_Domain": mail_domain,
        "DKIM_Signing_Domain": dkim_d,
        "SPF_Aligned": spf_aligned,
        "DKIM_Aligned": dkim_aligned,
        "DMARC_Authentication_Status": "PASS" if dmarc_pass else "FAIL"
    }

def detect_aitm_proxy_indicators(request_headers: Dict[str, str], set_cookies: List[str]) -> List[Dict[str, str]]:
    """
    Inspects HTTP request/response headers for signatures characteristic of
    Adversary-in-the-Middle (AiTM) reverse proxies like Evilginx/Modlishka.
    """
    findings = []
    
    # 1. Reverse proxy forwarded headers
    forwarded = request_headers.get("X-Forwarded-Host", "")
    host = request_headers.get("Host", "")
    if forwarded and host and (forwarded.lower() != host.lower()):
        findings.append({
            "Indicator": "PROXY_HOST_HEADER_MISMATCH",
            "Detail": f"Host ({host}) diverges from X-Forwarded-Host ({forwarded}).",
            "Severity": "HIGH"
        })

    # 2. Session cookie capture inspection
    sensitive_cookie_names = ["ESTSAUTH", "ESTSAUTHPERSISTENT", "okta_session", "session_token"]
    for cookie in set_cookies:
        for name in sensitive_cookie_names:
            if name.lower() in cookie.lower():
                findings.append({
                    "Indicator": "CRITICAL_SESSION_COOKIE_EXPOSED",
                    "Detail": f"Sensitive session cookie '{name}' intercepted without origin-bound isolation.",
                    "Severity": "CRITICAL"
                })

    return findings

def generate_homoglyph_permutations(domain: str) -> List[Dict[str, str]]:
    """
    Demonstrates Cyrillic/Greek IDN homoglyph punycode conversions (RFC 3492).
    Substitutes Latin characters with visually identical Cyrillic characters.
    """
    homoglyphs = {'a': 'а', 'c': 'с', 'e': 'е', 'i': 'і', 'o': 'о', 'p': 'р', 'x': 'х'}
    permutations = []
    
    parts = domain.split('.')
    name = parts[0]
    tld = '.'.join(parts[1:])
    
    for i, ch in enumerate(name):
        if ch.lower() in homoglyphs:
            spoofed_name = name[:i] + homoglyphs[ch.lower()] + name[i+1:]
            spoofed_domain = f"{spoofed_name}.{tld}"
            punycode = spoofed_domain.encode('idna').decode('ascii')
            permutations.append({
                "Visual_Deception": spoofed_domain,
                "Punycode_Wire_Format": punycode,
                "Target_Char": ch,
                "Substituted_Char": homoglyphs[ch.lower()]
            })
            
    return permutations

def run_self_tests():
    print("[*] Running Phishing Architecture & Email Security Engine Self-Tests...")

    # Test 1: Hardened DMARC Record Evaluation
    hardened_dmarc = "v=DMARC1; p=reject; sp=reject; pct=100; aspf=s; adkim=s; rua=mailto:dmarc-rua@corp.test;"
    dmarc_res = evaluate_dmarc_record(hardened_dmarc)
    assert dmarc_res["Is_Fully_Enforced"] is True
    assert dmarc_res["SPF_Alignment_Mode"] == "STRICT"
    assert "LOW" in dmarc_res["Risk_Assessment"]
    print("[+] Test 1 Passed: Hardened DMARC policy parsed and verified as fully enforced.")

    # Test 2: Insecure p=none DMARC Record Evaluation
    weak_dmarc = "v=DMARC1; p=none; rua=mailto:monitoring@corp.test;"
    weak_res = evaluate_dmarc_record(weak_dmarc)
    assert weak_res["Is_Fully_Enforced"] is False
    assert "HIGH" in weak_res["Risk_Assessment"]
    print("[+] Test 2 Passed: Insecure DMARC p=none identified as high risk.")

    # Test 3: Recursive SPF Lookup Traversal & 10-Lookup PermError
    # Build mock DNS database with recursive includes
    mock_dns = {
        "corp.test": "v=spf1 ip4:192.0.2.1 include:_spf.serviceA.test include:_spf.serviceB.test -all",
        "_spf.serviceA.test": "v=spf1 include:_sub1.serviceA.test include:_sub2.serviceA.test ~all",
        "_sub1.serviceA.test": "v=spf1 ip4:198.51.100.0/24 -all",
        "_sub2.serviceA.test": "v=spf1 include:_nested.serviceA.test -all",
        "_nested.serviceA.test": "v=spf1 ip4:203.0.113.5 -all",
        "_spf.serviceB.test": "v=spf1 ip4:198.51.100.50 -all"
    }
    lookups, visited, is_permerror = calculate_recursive_spf_lookups("corp.test", mock_dns)
    # Total lookups:
    # corp.test: 2 includes (serviceA, serviceB)
    # serviceA: 2 includes (sub1, sub2)
    # sub2: 1 include (nested)
    # Total = 5 lookups (<= 10)
    assert lookups == 5
    assert is_permerror is False
    print(f"[+] Test 3 Passed: SPF recursive tree resolved 5 lookups without PermError.")

    # Test 4: Breaching 10-Lookup Limit
    mock_dns_permerror = {
        "huge.test": "v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test -all",
        "a.test": "v=spf1 ip4:10.0.0.1 -all", "b.test": "v=spf1 ip4:10.0.0.2 -all",
        "c.test": "v=spf1 ip4:10.0.0.3 -all", "d.test": "v=spf1 ip4:10.0.0.4 -all",
        "e.test": "v=spf1 ip4:10.0.0.5 -all", "f.test": "v=spf1 ip4:10.0.0.6 -all",
        "g.test": "v=spf1 ip4:10.0.0.7 -all", "h.test": "v=spf1 ip4:10.0.0.8 -all",
        "i.test": "v=spf1 ip4:10.0.0.9 -all", "j.test": "v=spf1 ip4:10.0.0.10 -all",
        "k.test": "v=spf1 ip4:10.0.0.11 -all"
    }
    bad_lookups, _, perm_detected = calculate_recursive_spf_lookups("huge.test", mock_dns_permerror)
    assert bad_lookups > 10
    assert perm_detected is True
    print(f"[+] Test 4 Passed: Detected RFC 7208 PermError on {bad_lookups} lookups.")

    # Test 5: DMARC Identifier Alignment
    align_res = evaluate_identifier_alignment(
        header_from="cfo@corporate.corp",
        mail_from="mailer@corp.marketing-partner.com",
        dkim_domain="corporate.corp",
        aspf_mode="r",
        adkim_mode="r"
    )
    assert align_res["DKIM_Aligned"] is True
    assert align_res["DMARC_Authentication_Status"] == "PASS"
    print("[+] Test 5 Passed: DKIM alignment validated and passed DMARC evaluation.")

    # Test 6: AiTM Reverse Proxy Indicator Detection
    sample_headers = {"Host": "login.evil-aitm-proxy.test", "X-Forwarded-Host": "login.microsoftonline.com"}
    sample_cookies = ["ESTSAUTH=eyJh****REDACTED; Path=/; Secure; HttpOnly"]
    aitm_alerts = detect_aitm_proxy_indicators(sample_headers, sample_cookies)
    assert len(aitm_alerts) == 2
    assert aitm_alerts[0]["Indicator"] == "PROXY_HOST_HEADER_MISMATCH"
    assert aitm_alerts[1]["Indicator"] == "CRITICAL_SESSION_COOKIE_EXPOSED"
    print("[+] Test 6 Passed: AiTM reverse proxy header and session token alerts triggered successfully.")

    # Test 7: Homoglyph Punycode Generation
    homoglyphs = generate_homoglyph_permutations("apple.com")
    assert len(homoglyphs) > 0
    assert homoglyphs[0]["Punycode_Wire_Format"].startswith("xn--")
    print(f"[+] Test 7 Passed: Generated valid IDN Punycode homoglyph: {homoglyphs[0]['Punycode_Wire_Format']}")

    print("[*] All Phishing & Email Security Analysis tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
