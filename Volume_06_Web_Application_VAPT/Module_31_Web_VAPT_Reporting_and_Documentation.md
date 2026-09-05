# Volume 06: Web Application VAPT
# Module 31: Web VAPT Reporting, Vulnerability Documentation & Remediation Engineering

---

## 1. Learning Objectives

By completing this module, security practitioners, lead penetration testers, and application security auditors will be able to:
1. **Construct Enterprise VAPT Deliverables**: Author professional, production-ready assessment reports tailored for dual audiences: Executive Leadership and Engineering Teams.
2. **Calculate Deterministic Severity Metrics**: Compute and calibrate vulnerability scores using the Common Vulnerability Scoring System (CVSS v3.1 and CVSS v4.0) according to official FIRST.org specifications.
3. **Map Weakness Taxonomies**: Accurately categorize findings across Common Weakness Enumeration (CWE), OWASP Top 10 (2021), and OWASP ASVS v4.0.3 standards.
4. **Implement the 14-Point Finding Dossier**: Structure reproducible, evidence-based technical findings incorporating raw HTTP requests, raw HTTP responses, non-destructive benign proofs-of-concept, and secret redaction.
5. **Formulate Framework-Specific Remediation**: Provide actionable, production-ready code patches (e.g., ORM parameterization, tenancy boundaries, contextual encoders) rather than generic platitudes.
6. **Govern the Remediation Lifecycle**: Establish formal remediation SLAs, track Mean-Time-To-Remediate (MTTR), and execute the Retest and Letter of Attestation workflow.

---

## 2. Prerequisites & Operational Requirements

To successfully master the concepts and practical exercises in this module, engineers require:
* **Vulnerability & Architecture Knowledge**: Deep understanding of OWASP Top 10 vulnerabilities, root cause analysis, and browser/server communication ([Module 30](file:///home/kali/Ethical_Hacking_VAPT_Master_Notes/Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md)).
* **Risk Quantification Literacy**: Familiarity with mathematical scoring metrics, probability distributions, and business impact modeling.
* **Scripting Tools**: Python 3.8+ with standard libraries (`math`, `re`, `json`) for executing local CVSS calculators and document compilers.

---

## 3. What Is It? (Architecture & Definitions)

Vulnerability reporting is the definitive, tangible deliverable of a security assessment or penetration test. 

A penetration test is only as valuable as the clarity, precision, and actionability of its final report. An assessment that discovers a critical remote code execution vulnerability is an operational failure if the deliverable is so poorly documented that the client's engineering team cannot reproduce the issue, understand its root cause, or deploy the necessary code patch before malicious actors exploit it.

Professional documentation bridges the critical communication divide between offensive verification and defensive engineering:
* **For Executive Leadership & Board Members**: Quantifies business risk, evaluates financial and regulatory exposure (e.g., GDPR, HIPAA, PCI-DSS), and presents prioritized strategic roadmaps.
* **For Software Engineers & DevOps**: Delivers deterministic, reproducible technical proofs, exact parameter locations, root cause code analysis, and drop-in code patches.

---

## 4. Deep Architecture: Enterprise VAPT Report Structure & CVSS Equations

```mermaid
graph TD
    subgraph "Enterprise VAPT Deliverable Architecture"
        DOC["Formal Deliverable Document"]
        
        subgraph "Section I: Executive Leadership"
            EXEC["Executive Summary"]
            RISK["Aggregate Risk & Threat Profile"]
            SEV_CHART["Severity Distribution Chart"]
            STRAT["Strategic 30/60/90 Day Roadmap"]
        end
        
        subgraph "Section II: Scope & Methodology"
            SCOPE["Authorized Scope (CIDRs, URLs, APIs)"]
            RULES["Rules of Engagement & Timing Constraints"]
            METH["Testing Methodology (OWASP WSTG, PTES)"]
        end
        
        subgraph "Section III: Technical Engineering Findings"
            MATRIX["Summary Matrix of Findings"]
            DOSSIER["14-Point Finding Dossiers (VAPT-01 to VAPT-N)"]
        end
        
        subgraph "Section IV: Verification & Closure"
            RETEST["Retest Verification Log"]
            ATTEST["Formal Letter of Attestation"]
        end
    end

    DOC --> EXEC
    DOC --> RISK
    DOC --> SEV_CHART
    DOC --> STRAT
    DOC --> SCOPE
    DOC --> RULES
    DOC --> METH
    DOC --> MATRIX
    DOC --> DOSSIER
    DOC --> RETEST
    DOC --> ATTEST
```

### 4.1 CVSS v3.1 Mathematical Scoring Architecture
The Common Vulnerability Scoring System (CVSS) calculates a score between $0.0$ and $10.0$ based on three metric groups: **Base**, **Temporal**, and **Environmental**. The Base Score reflects intrinsic qualities across two sub-scores: **Exploitability** and **Impact**.

#### 1. The Impact Sub-Score (ISS)
$$\text{ISS} = 1 - [(1 - \text{Impact}_{\text{Conf}}) \times (1 - \text{Impact}_{\text{Integ}}) \times (1 - \text{Impact}_{\text{Avail}})]$$

#### 2. Scope Impact Calculation
* **Scope Unchanged ($S = U$)**:
  $$\text{Impact} = 6.42 \times \text{ISS}$$
* **Scope Changed ($S = C$)**:
  $$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$

#### 3. Exploitability Sub-Score
$$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$

Where:
* **Attack Vector (AV)**: Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.20)
* **Attack Complexity (AC)**: Low (0.77), High (0.44)
* **Privileges Required (PR)**:
  * Scope Unchanged: None (0.85), Low (0.62), High (0.27)
  * Scope Changed: None (0.85), Low (0.68), High (0.50)
* **User Interaction (UI)**: None (0.85), Required (0.62)

#### 4. Base Score Finalization
$$\text{BaseScore} = \begin{cases} 
0 & \text{if Impact} \le 0 \\
\text{Roundup}(\min[(\text{Impact} + \text{Exploitability}), 10.0]) & \text{if Scope Unchanged} \\
\text{Roundup}(\min[1.08 \times (\text{Impact} + \text{Exploitability}), 10.0]) & \text{if Scope Changed}
\end{cases}$$

---

## 5. How It Works: The Assessment & Retest Lifecycle

```
[ Phase 1: Real-Time Artifact Logging ]
      | Capture raw request/response pairs & steps as defects are verified.
      v
[ Phase 2: Finding Dossier Compilation ]
      | Author technical finding dossiers with root cause analysis & code patches.
      v
[ Phase 3: Internal Peer Review & Quality Assurance ]
      | Senior auditor validates reproduction commands, CVSS vectors, and secret redaction.
      v
[ Phase 4: Executive Debrief & Encrypted Delivery ]
      | Present findings to leadership; deliver encrypted PDF/markdown deliverables.
      v
[ Phase 5: Remediation Sprint (Engineering Team) ]
      | Development team implements code patches within contracted SLA windows.
      v
[ Phase 6: Retest & Verification ]
      | Auditor re-executes exact benign PoCs against patched staging environments.
      v
[ Phase 7: Formal Letter of Attestation ]
      | Issue formal retest certificate documenting resolved vs. open defects.
```

---

## 6. Security Perspective: Risk Communication & Calibration

### 6.1 Bridging the Communication Divide
* **The Executive Perspective**: Leadership evaluates risks in terms of financial liability, business disruption, compliance violations (PCI-DSS non-compliance fines, GDPR Article 83 penalties), and brand reputation. Findings must highlight business impact scenarios without technical jargon.
* **The Engineering Perspective**: Software developers need deterministic precision: the vulnerable file, line number, input parameter, exact HTTP request payload, and concrete unit test assertions verifying the patch.

### 6.2 Eliminating Severity Inflation
Amateur testers frequently inflate severity ratings (e.g., labeling a missing `X-Content-Type-Options` header as "High Severity"). This practice destroys credibility with engineering teams, triggers alert fatigue, and diverts engineering resources away from critical authorization and injection defects. Base scores must adhere strictly to the FIRST.org CVSS specification.

---

## 7. Auditing Methodology: The Standard 14-Point Finding Dossier

Every vulnerability documented in an enterprise VAPT deliverable must conform to the 14-point Finding Dossier schema:

```markdown
### [VAPT-01] Broken Object Level Authorization (BOLA) Exposing Sensitive Tenant Invoices

1.  **Vulnerability Title**: Broken Object Level Authorization (BOLA) on Customer Invoice Endpoint
2.  **Tracking ID**: VAPT-01
3.  **Severity Rating**: Medium (Base Score: 6.5 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
4.  **CWE Classification**: CWE-639: Authorization Bypass Through User-Controlled Key
5.  **OWASP Category**: A01:2021 – Broken Access Control
6.  **Target Asset**: `https://billing.staging.corp/api/v2/invoices/{id}`
7.  **Vulnerable Parameter**: `id` (HTTP GET Path Parameter)
8.  **Required Privileges**: Authenticated Standard Customer Session (`role: customer`)
9.  **Executive Summary**: An authorization bypass allows authenticated customers to view invoices of other enterprise tenants by altering the numeric ID in the URL.
10. **Technical Description & Root Cause**: The backend controller uses the user-supplied `id` directly in a database query without constraining the query with the requesting session's `tenant_id`.
11. **Benign Proof-of-Concept & Reproduction Steps**:
    1. Authenticate as Customer A (`tenant_id: 10`).
    2. Intercept the legitimate invoice request (`GET /api/v2/invoices/101`).
    3. Modify the path parameter to `201` (belonging to Customer B, `tenant_id: 20`):
       ```http
       GET /api/v2/invoices/201 HTTP/1.1
       Host: billing.staging.corp
       Authorization: Bearer eyJh****REDACTED
       ```
    4. Observe that the server returns Customer B's proprietary invoice data in full.
12. **Tactical Code Remediation (Immediate)**:
    ```javascript
    const invoice = await prisma.invoice.findFirst({
      where: { id: invoiceId, tenantId: req.user.tenantId }
    });
    ```
13. **Strategic Defense-in-Depth (Architectural)**: Implement centralized Policy Enforcement Point (PEP) middleware enforcing tenant isolation across all object fetch operations.
14. **Contractual Remediation SLA**: 14 Days.
```

---

## 8. Tooling Deep-Dive: Automated Report Compilers

### 8.1 Markdown to Enterprise PDF Compilation via Pandoc & WeasyPrint

```bash
# Compile structured Markdown dossiers into a styled executive PDF deliverable
pandoc 00_cover.md 01_exec_summary.md 02_scope.md findings/*.md \
       -o Enterprise_VAPT_Final_Report.pdf \
       --from markdown+yaml_metadata_block \
       --table-of-contents \
       --toc-depth=3 \
       --number-sections \
       --pdf-engine=weasyprint \
       --css=enterprise_theme.css
```

---

## 9. Practical Lab: Standalone VAPT Reporting & CVSS v3.1 Engine

Deploy this standalone script to calculate CVSS v3.1 scores mathematically, perform automated secret redaction, and compile standardized Finding Dossiers.

Save as `vapt_report_and_cvss_engine.py`:

```python
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
```

---

## 10. Evidence & Verification: Secret Redaction Standards

When compiling assessment deliverables, reports are routinely distributed across broad engineering, management, and compliance groups. Disclosing live secrets violates enterprise confidentiality:

| Secret Category | Raw Example In Intercepted Traffic | Mandatory Redacted Presentation In Report |
| :--- | :--- | :--- |
| **API Keys** | `sec_live_9941a88b72c91823ab1099f` | `sec_****REDACTED` |
| **JWT Tokens** | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` | `eyJh****REDACTED` |
| **Passwords** | `DatabasePassword=SuperP@ssw0rd2026!` | `DatabasePassword=Supe****REDACTED` |
| **Cloud IAM Keys** | `AKIAIOSFODNN7EXAMPLE` | `AKIAIOSF****REDACTED` |

---

## 11. Telemetry & Defensive Detection: Tracking MTTR Metrics

Enterprise security operations must track remediation performance using standardized metrics:
* **Mean-Time-To-Remediate (MTTR)**:
  $$\text{MTTR} = \frac{\sum (\text{Closure Date} - \text{Discovery Date})}{\text{Total Verified Findings}}$$
* **Vulnerability Aging Alerting**: Automated notifications sent to engineering leads when findings exceed 50%, 75%, and 90% of their contracted SLA window.

---

## 12. Mitigation: Dual-Track Remediation Guidance

Every documented finding must provide two distinct remediation recommendations:
1. **Tactical Fix (Short-Term Hotfix)**: Immediate source code patch or configuration change resolving the specific vulnerable endpoint.
2. **Strategic Defense-in-Depth (Long-Term Architecture)**: Architectural controls that eliminate the entire defect class systematically (e.g., deploying central authorization middleware, database-level Row Level Security, or input-agnostic prepared statements).

---

## 13. CIS & NIST Hardening Controls: Enterprise Remediation SLA Matrix

| Finding Severity | CVSS v3.1 Range | Contractual SLA Window | Verification Requirement |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | $9.0 - 10.0$ | **48 Hours** | Hotfix deployment + immediate consultant retest sign-off |
| **HIGH** | $7.0 - 8.9$ | **14 Days** | Sprint hotfix + automated regression test coverage |
| **MEDIUM** | $4.0 - 6.9$ | **30 Days** | Standard production release cycle |
| **LOW** | $0.1 - 3.9$ | **90 Days** | Technical debt backlog or formal accepted risk sign-off |
| **INFORMATIONAL** | $0.0$ | Discretionary | Hardening recommendation; reviewed during annual audits |

---

## 14. Real-World Case Studies

### Case Study: Ambiguous PoC Resulting in Extended Vulnerability Exposure
During an authorized security audit of an enterprise financial service, an auditor reported an IDOR bug simply stating: *"The accounts endpoint lacks authorization."* No specific account IDs, raw HTTP requests, or parameters were provided.
* **Operational Consequence**: The development team was unable to identify the flawed controller from among 200 account-related routes, marked the ticket "Cannot Reproduce," and closed it. Three months later, the exact unauthenticated endpoint was exploited externally.
* **Auditing Resolution**: Re-auditing using the **14-point Finding Dossier** format provided the exact route, session headers, and verified curl commands, allowing the development team to isolate the flawed controller and deploy a verified code patch within 4 hours.

---

## 15. Common Pitfalls & Anti-Patterns

```
❌ ANTI-PATTERN 1: Dumping Unprocessed Scanner Output
   Exporting a 250-page raw PDF from an automated scanner and presenting it as a penetration test report.
   Contains 80% false positives, lacks business context, and destroys trust with executive leadership.
   ✔ CORRECT: Deliver curated, manually verified findings containing reproducible benign proofs of concept.

❌ ANTI-PATTERN 2: Providing Generic Remediation Advice
   Telling developers to "Sanitize all inputs" or "Implement access control."
   Provides zero engineering value and leads to recurring vulnerabilities.
   ✔ CORRECT: Deliver production-ready code patches matching the application's exact programming language and framework.

❌ ANTI-PATTERN 3: Exposing Unredacted Live Customer PII and Secrets
   Including unmasked production customer records, Social Security Numbers, or active API keys in reports.
   Violates data privacy regulations (GDPR, HIPAA) and creates a secondary data breach risk.
   ✔ CORRECT: Redact all sensitive tokens and personal data to their first 4 characters followed by wildcard masking.
```

---

## 16. Professional vs. Naive Methodology

| Operational Phase | Naive / Novice Approach | Professional Application Security Auditor Approach |
| :--- | :--- | :--- |
| **Finding Documentation** | Writes vague one-line summaries without step-by-step reproduction instructions. | Provides the 14-point Finding Dossier with exact curl commands and parameter names. |
| **Severity Scoring** | Assigns subjective severity based on personal feeling or scanner defaults. | Calculates deterministic CVSS v3.1/v4.0 vectors adhering strictly to FIRST.org formulas. |
| **Remediation Advice** | Quotes generic textbook definitions ("Use defense in depth"). | Supplies concrete code patches, framework-specific configurations, and regression tests. |
| **Engagement Closure** | Delivers report and disconnects from the client. | Guides the client through remediation sprints, conducts formal retests, and issues Attestation Letters. |

---

## 17. Graded Knowledge Check & Interview Questions

### Beginner Level
1. **Question**: What is the difference between CVSS Base Metrics, Temporal Metrics, and Environmental Metrics?
   * *Answer*: Base Metrics represent intrinsic, immutable characteristics of a vulnerability (e.g., Attack Vector, Impact on Confidentiality). Temporal Metrics measure attributes that change over time (e.g., exploit code availability, official vendor patch status). Environmental Metrics customize the score to a specific organization's deployment context (e.g., mitigating architectural firewalls, asset criticality).
2. **Question**: Why is a penetration test report that lacks an Executive Summary considered incomplete?
   * *Answer*: Executive leaders (CISOs, CTOs, Board Members) allocate security budgets and prioritize organizational risk, but rarely have time or technical depth to read hundreds of raw HTTP requests. The Executive Summary provides the business impact context, aggregate risk ratings, and strategic resource allocation guidance necessary for leadership decision-making.

### Intermediate Level
3. **Question**: Explain the CVSS v3.1 "Scope" metric, and give an example of when Scope changes from Unchanged (U) to Changed (C).
   * *Answer*: Scope refers to whether a vulnerability in one software component impacts resources beyond its immediate execution authority. Scope is **Unchanged (U)** when the compromised component and impacted resource belong to the same security authority (e.g., SQLi in a web app accessing the web app's database). Scope is **Changed (C)** when the vulnerability allows access to resources managed by a different security authority (e.g., Server-Side Request Forgery on a web server allowing unauthorized access to the underlying AWS cloud metadata service).

### Advanced / Scenario-Based
4. **Question**: A development team disputes a High-severity finding (CVSS 8.1), arguing that the affected endpoint is "hidden and not linked anywhere in the web UI." How do you defend the finding and score professionally?
   * *Answer*: Explain that security through obscurity is not an access control mechanism. Modern attackers and automated crawlers discover unlinked endpoints via brute-force directory fuzzing, JavaScript source map mining, historical archive indexing (Wayback Machine), and DNS enumeration. In CVSS v3.1, Attack Vector remains Network (N) and Attack Complexity remains Low (L) because no specialized conditions or access keys are required once the route is known. Reiterate that authorization must be enforced on every stateful endpoint regardless of UI visibility.

---

## 18. Progressive Hands-on Exercises

### Level 1: CVSS v3.1 Calculation & Vector Formulation (Beginner)
* Run `vapt_report_and_cvss_engine.py`.
* Formulate CVSS v3.1 vectors and calculate base scores for:
  1. Stored XSS in an internal administrative comment system requiring admin interaction.
  2. Unauthenticated Remote Code Execution in a public-facing API gateway.

### Level 2: Authoring a 14-Point Finding Dossier (Intermediate)
* Using the output from the Module 30 lab (SQL Injection or BOLA), draft a complete 14-point Finding Dossier following the standard schema in Section 7.
* Ensure all session cookies and tokens are strictly masked using the redaction engine.

### Level 3: Automated PDF Report Compilation (Advanced)
* Structure a multi-part Markdown report consisting of `00_cover.md`, `01_exec_summary.md`, and `02_findings.md`.
* Use `pandoc` with WeasyPrint or LaTeX to compile the documents into a styled enterprise PDF report with an automated Table of Contents.

---

## 19. Key Takeaways

1. **Reports Are the Product**: The value of a security assessment is measured entirely by the actionability and clarity of the final deliverable.
2. **Dual-Audience Requirement**: Deliverables must satisfy both non-technical executive leadership and technical engineering teams.
3. **Deterministic CVSS Scoring**: Eliminate subjective severity inflation by adhering strictly to FIRST.org mathematical equations.
4. **Redact All Production Secrets**: Never disclose raw live API keys, session tokens, or customer PII in assessment deliverables.
5. **Close the Loop via Retesting**: A penetration test is not complete until identified findings are remediated, retested, and certified.

---

## 20. Authoritative References

* **FIRST CVSS v3.1 Specification**: Common Vulnerability Scoring System (`first.org/cvss/v3.1/specification-document`).
* **FIRST CVSS v4.0 Specification**: Next-Generation Common Vulnerability Scoring System (`first.org/cvss/v4.0`).
* **Penetration Testing Execution Standard (PTES)**: Section 7 – Reporting Phase (`pentest-standard.org`).
* **OWASP Vulnerability Reporting Guidelines**: Best Practices for Documenting Web Flaws (`owasp.org`).
* **NIST SP 800-115**: *Technical Guide to Information Security Testing and Assessment*.
