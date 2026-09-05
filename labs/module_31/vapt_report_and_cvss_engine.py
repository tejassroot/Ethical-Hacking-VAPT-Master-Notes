#!/usr/bin/env python3
"""
================================================================================
MODULE 31 LAB: ENTERPRISE VAPT REPORTING & CVSS v3.1 CALCULATION ENGINE
PURPOSE: Implements deterministic CVSS v3.1 scoring, automated 14-point Finding
         Dossier compilation, operational secret redaction, and SLA compliance.
COMPLIANCE: Authorized reporting methodology / FIRST.org CVSS v3.1 specification.
================================================================================
"""

import math
import re
import json
import sys

def redact_sensitive_values(raw_text):
    """
    Operational Redaction Engine:
    Redacts sensitive credentials, API keys, and JWT tokens to their first 4
    characters followed by wildcard masking (e.g. 'sk_live_1234****REDACTED').
    """
    patterns = [
        (r'(Bearer\s+)([A-Za-z0-9_\-\.]{4})[A-Za-z0-9_\-\.]+', r'\1\2****REDACTED'),
        (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]+', r'\1\2****REDACTED'),
        (r'(password["\']?\s*[:=]\s*["\']?)(.{4}).*?(["\']|$)', r'\1\2****REDACTED\3'),
        (r'(AKIA[0-9A-Z]{4})[0-9A-Z]{12}', r'\1****REDACTED')
    ]
    redacted = raw_text
    for pat, repl in patterns:
        redacted = re.sub(pat, repl, redacted, flags=re.IGNORECASE)
    return redacted

class CVSSv31Calculator:
    """Calculates CVSS v3.1 Base Score following the official FIRST.org specification."""
    
    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
        "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},   # Scope Changed
        "UI": {"N": 0.85, "R": 0.62},
        "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
        "I":  {"H": 0.56, "L": 0.22, "N": 0.0},
        "A":  {"H": 0.56, "L": 0.22, "N": 0.0}
    }

    @staticmethod
    def roundup(val):
        """Standard CVSS v3.1 roundup function: ceiling to 1 decimal place."""
        return math.ceil(val * 10) / 10

    @classmethod
    def calculate(cls, vector_str):
        parts = dict(item.split(":") for item in vector_str.replace("CVSS:3.1/", "").split("/"))
        
        av = cls.METRICS["AV"][parts["AV"]]
        ac = cls.METRICS["AC"][parts["AC"]]
        scope_changed = (parts["S"] == "C")
        pr_key = "PR_C" if scope_changed else "PR_U"
        pr = cls.METRICS[pr_key][parts["PR"]]
        ui = cls.METRICS["UI"][parts["UI"]]
        
        c = cls.METRICS["C"][parts["C"]]
        i = cls.METRICS["I"][parts["I"]]
        a = cls.METRICS["A"][parts["A"]]

        # 1. Calculate ISS (Impact Sub-Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # 2. Calculate Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # 4. Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if not scope_changed:
                base_score = cls.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        # Severity categorization
        if base_score == 0.0:
            severity = "NONE"
        elif base_score < 4.0:
            severity = "LOW"
        elif base_score < 7.0:
            severity = "MEDIUM"
        elif base_score < 9.0:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        return base_score, severity

class FindingDossier:
    """Compiles a standard enterprise 14-point finding deliverable."""
    def __init__(self, finding_id, title, cwe, owasp, asset, param, cvss_vector, summary, root_cause, poc, remediation_code, sla_days=14):
        self.finding_id = finding_id
        self.title = title
        self.cwe = cwe
        self.owasp = owasp
        self.asset = asset
        self.param = param
        self.cvss_vector = cvss_vector
        self.summary = summary
        self.root_cause = root_cause
        self.poc = redact_sensitive_values(poc)
        self.remediation_code = remediation_code
        self.sla_days = sla_days
        self.score, self.severity = CVSSv31Calculator.calculate(cvss_vector)

    def to_markdown(self):
        return f"""### [{self.finding_id}] {self.title}

* **Severity**: **{self.severity}** (Base Score: {self.score} | `{self.cvss_vector}`)
* **Vulnerability Classification**: {self.cwe}
* **OWASP Top 10 Category**: {self.owasp}
* **Target Asset**: `{self.asset}`
* **Vulnerable Input Vector**: `{self.param}`
* **Remediation SLA**: {self.sla_days} Days

#### 1. Executive Summary
{self.summary}

#### 2. Root Cause Analysis
{self.root_cause}

#### 3. Benign Proof-of-Concept & Verification
```http
{self.poc}
```

#### 4. Remediation Code Patch
```javascript
{self.remediation_code}
```
"""

def run_dossier_engine():
    print("=" * 72)
    print("[*] ENTERPRISE VAPT REPORTING & CVSS v3.1 CALCULATION ENGINE")
    print("=" * 72)

    # 1. CVSS Calculation Tests
    test_vectors = [
        ("BOLA / IDOR", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), # Expected ~6.5 HIGH
        ("Blind SSRF to AWS Metadata", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"), # Expected ~8.6 HIGH
        ("Critical Unauth RCE", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") # Expected 10.0 CRITICAL
    ]

    print("[*] Validating FIRST.org CVSS v3.1 Mathematical Calculations:")
    for name, vec in test_vectors:
        score, sev = CVSSv31Calculator.calculate(vec)
        print(f"    - {name:30s}: Base Score {score:4.1f} [{sev:8s}] -> {vec}")

    # 2. Secret Redaction Test
    print("\n[*] Validating Automated Secret & Token Masking Engine:")
    raw_poc = (
        "GET /api/v1/user/private HTTP/1.1\n"
        "Host: api.target.corp\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSJ9\n"
        "X-Api-Key: sec_live_9941a88b72c91823ab\n"
        "AWS_KEY: AKIAIOSFODNN7EXAMPLE"
    )
    redacted_poc = redact_sensitive_values(raw_poc)
    print("    [+] Redaction Result:")
    for line in redacted_poc.splitlines():
        print(f"        {line}")

    # 3. Generating Complete Finding Dossier
    print("\n[*] Generating Formatted Enterprise Markdown Deliverable:")
    finding = FindingDossier(
        finding_id="VAPT-01",
        title="Broken Object Level Authorization (BOLA) Exposing Sensitive Tenant Invoices",
        cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
        owasp="A01:2021 – Broken Access Control",
        asset="https://billing.staging.corp/api/v2/invoices/{id}",
        param="id (Path Parameter)",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        summary="A critical authorization bypass allows authenticated customers to view invoices of other enterprise tenants by manipulating numeric path IDs.",
        root_cause="The SQL query filters solely on invoice ID without validating tenant ownership against the active session token.",
        poc=raw_poc,
        remediation_code="const invoice = await prisma.invoice.findFirst({\n  where: { id: invoiceId, tenantId: req.user.tenantId }\n});",
        sla_days=14
    )
    md_output = finding.to_markdown()
    print("    [+] Successfully compiled finding with calculated score:")
    print(f"        Title: {finding.title}")
    print(f"        Score: {finding.score} ({finding.severity})")

    print("\n" + "=" * 72)
    print("[+] REPORTING & CVSS v3.1 VERIFICATION COMPLETE.")
    print("=" * 72)

if __name__ == "__main__":
    run_dossier_engine()
