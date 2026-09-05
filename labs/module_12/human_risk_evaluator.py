#!/usr/bin/env python3
"""
================================================================================
MODULE 12 LAB: HUMAN RISK & PHISHING LURE PSYCHOMETRIC ANALYZER
PURPOSE: Parses email headers and text to score psychological urgency,
         authority coercion, and domain spoofing indicators.
COMPLIANCE: Authorized testing only / Educational human-risk simulation.
================================================================================
"""

import re
import sys

PSYCHOLOGICAL_TRIGGERS = {
    "Urgency & Fear": [
        "immediately", "urgent", "suspended", "unauthorized", "action required",
        "terminated", "expire", "within 24 hours", "locked", "penalty"
    ],
    "Authority & Hierarchy": [
        "ciso", "chief executive", "legal counsel", "compliance officer",
        "human resources", "internal revenue", "audit committee", "it support"
    ],
    "Financial Incentive / Curiosity": [
        "payroll", "bonus", "salary increase", "invoice", "direct deposit",
        "wire transfer", "confidential settlement", "gift card"
    ]
}

def analyze_phishing_lure(email_subject, email_body, sender_domain, claimed_organization):
    print("=" * 72)
    print("[*] EXECUTING HUMAN RISK & PSYCHOMETRIC LURE EVALUATION")
    print("=" * 72)

    combined_text = (email_subject + " " + email_body).lower()
    total_score = 0
    findings = []

    claimed_clean = claimed_organization.lower().replace(" ", "")
    sender_clean = sender_domain.lower()
    
    if claimed_clean not in sender_clean:
        total_score += 35
        findings.append(f"CRITICAL DOMAIN MISMATCH: Sender domain '{sender_domain}' does not align with claimed entity '{claimed_organization}' (+35 pts)")
    else:
        findings.append(f"Domain Alignment Verified: '{sender_domain}' matches claimed entity.")

    for category, triggers in PSYCHOLOGICAL_TRIGGERS.items():
        matched_words = [word for word in triggers if re.search(r'\b' + re.escape(word) + r'\b', combined_text)]
        if matched_words:
            weight = len(matched_words) * 10
            total_score += weight
            findings.append(f"Psychological Trigger [{category}]: Found {len(matched_words)} cue(s) ({', '.join(matched_words)}) (+{weight} pts)")

    if "http://" in combined_text or "https://" in combined_text or "click here" in combined_text:
        total_score += 15
        findings.append("Call-to-Action Link Detected (+15 pts)")

    print(f"[+] Subject: '{email_subject}'")
    print(f"[+] Sender Domain: '{sender_domain}' (Claimed: '{claimed_organization}')")
    print("\n[*] Evaluation Breakdown:")
    for finding in findings:
        print(f"    - {finding}")

    print("\n" + "=" * 72)
    risk_level = "CRITICAL RISK (High Probability of Human Compromise)" if total_score >= 60 else \
                 "MODERATE RISK (Suspicious Characteristics)" if total_score >= 30 else \
                 "LOW RISK (Benign / Standard Operational Tone)"
    
    print(f"[+] Calculated Phishing Vulnerability Score: {total_score} / 100")
    print(f"[+] Overall Human Vulnerability Rating:    {risk_level}")
    print("=" * 72)

if __name__ == "__main__":
    sample_subj = "URGENT: Executive IT Support - VPN Credentials Expiring Within 24 Hours"
    sample_body = (
        "All employees must immediately connect to the secure benefits portal to verify their payroll "
        "and direct deposit information. This directive is issued by the Chief Executive and Legal Counsel. "
        "Failure to act within 24 hours will result in your account being locked. Click here to verify."
    )
    analyze_phishing_lure(sample_subj, sample_body, "corp-it-update.com", "Enterprise Corp")
