# Volume 12: Labs, Exercises, Checklists & Reference Material
# Authoritative References Library: Standards, RFCs, NIST, OWASP & Academic Citations

---

## 1. Overview

This document represents the master academic and technical bibliography supporting the entire 12-volume cybersecurity and VAPT curriculum. Every concept, protocol dissection, vulnerability root cause, and remediation pattern documented in this knowledge base is anchored in primary technical standards, authoritative RFCs, government publications, or foundational peer-reviewed computer science literature.

---

## 2. IETF Request for Comments (RFC Standards)

### 2.1 Web, Application & Transport Layer Protocols
* **RFC 9110**: *HTTP Semantics* (Obsoletes RFC 7230-7235). Defines standard HTTP methods, status codes, header field semantics, and content negotiation rules.
* **RFC 9112**: *HTTP/1.1*. Formally specifies HTTP/1.1 message framing, chunked transfer encoding, and pipelining rules.
* **RFC 9113**: *HTTP/2*. Formal binary framing layer, multiplexed streams, flow control, and HPACK header compression.
* **RFC 9114**: *HTTP/3*. HTTP semantics mapped over the QUIC transport protocol utilizing UDP.
* **RFC 9000**: *QUIC: A UDP-Based Multiplexed and Secure Transport*. Defines low-latency, encrypted-by-default transport mechanism.
* **RFC 8446**: *The Transport Layer Security (TLS) Protocol Version 1.3*. Eliminates insecure cipher suites, mandates forward secrecy (ECDHE), and establishes 1-RTT handshake.
* **RFC 5246**: *The Transport Layer Security (TLS) Protocol Version 1.2*. Foundation for legacy enterprise TLS implementations.
* **RFC 6455**: *The WebSocket Protocol*. Full-duplex communication channel over a single TCP connection initiated via HTTP Upgrade.
* **RFC 6265**: *HTTP State Management Mechanism (Cookies)*. Specifications for `Set-Cookie`, `HttpOnly`, `Secure`, and `SameSite` flags.
* **RFC 3986**: *Uniform Resource Identifier (URI): Generic Syntax*. Authoritative grammar for scheme, authority, path, query, and fragment parsing.

### 2.2 Email Architecture & Anti-Spoofing Protocols
* **RFC 5321**: *Simple Mail Transfer Protocol (SMTP)*. Core mail transmission protocol between Mail Transfer Agents (MTAs).
* **RFC 5322**: *Internet Message Format*. Syntax specifications for email message headers (`From:`, `To:`, `Received:`) and body structure.
* **RFC 7208**: *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*. DNS-based authorization mechanism for sending MTA IP addresses.
* **RFC 6376**: *DomainKeys Identified Mail (DKIM) Signatures*. Cryptographic signature specification for email header and body integrity.
* **RFC 7489**: *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*. Identifier alignment and policy enforcement framework.
* **RFC 8461**: *Mail Transfer Agent Strict Transport Security (MTA-STS)*. Eliminates opportunistic TLS downgrade on SMTP port 25 via HTTPS policy.
* **RFC 8460**: *SMTP TLS Reporting (TLSRPT)*. Standardized automated reporting mechanism for SMTP transport failures.
* **RFC 8617**: *The Authenticated Received Chain (ARC) Protocol*. Preserves email authentication status across intermediaries and forwarders.
* **RFC 7672**: *SMTP Security via Opportunistic DANE TLS*. Binds SMTP TLS certificates to DNSSEC via TLSA records.

### 2.3 Identity, Authentication & Networking Protocols
* **RFC 6749**: *The OAuth 2.0 Authorization Framework*. Specifications for authorization grants, authorization servers, and access tokens.
* **RFC 7519**: *JSON Web Token (JWT)*. Compact, URL-safe means of representing claims to be transferred between two parties.
* **RFC 4120**: *The Kerberos Network Authentication Service (V5)*. Core authentication protocol powering Active Directory Domain Services.
* **RFC 791**: *Internet Protocol (IPv4)*. DARPA Internet Program Protocol Specification.
* **RFC 793 / RFC 9293**: *Transmission Control Protocol (TCP) Specification*. Reliable stream delivery and state machine definitions.
* **RFC 1918**: *Address Allocation for Private Internets*. Designates IPv4 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
* **RFC 1928**: *SOCKS Protocol Version 5*. Framework for generic socket proxying across firewalls.

---

## 3. NIST Special Publications & FIPS Standards

* **NIST SP 800-115**: *Technical Guide to Information Security Testing and Assessment*. The federal benchmark for planning, executing, and documenting technical security assessments and penetration tests.
* **NIST SP 800-53 Rev. 5**: *Security and Privacy Controls for Information Systems and Organizations*. Comprehensive catalog of security controls organized across 20 control families (AC, IA, SC, SI).
* **NIST SP 800-63B**: *Digital Identity Guidelines: Authentication and Lifecycle Management*. Defines Authenticator Assurance Levels (AAL), credential rotation, and password complexity guidelines (deprecating mandatory special character rules in favor of length and breach checks).
* **NIST SP 800-45**: *Guidelines on Electronic Mail Security*. Recommendations for securing MTA relays, mail clients, and cryptographic transport.
* **NIST SP 800-30 Rev. 1**: *Guide for Conducting Risk Assessments*. Standardized risk assessment formula: $Risk = f(Threat, Vulnerability, Impact, Likelihood)$.
* **FIPS PUB 140-3**: *Security Requirements for Cryptographic Modules*. Federal benchmark validating hardware and software cryptographic implementations across Levels 1 through 4.
* **FIPS PUB 197**: *Advanced Encryption Standard (AES)*. Mathematical specification of the Rijndael algorithm for 128-, 192-, and 256-bit keys.

---

## 4. OWASP Standards & Methodologies

* **OWASP Web Security Testing Guide (WSTG v4.2)**: Comprehensive testing framework containing 12 test categories spanning 66 specific test cases.
* **OWASP Application Security Verification Standard (ASVS v4.0.3)**: Definitive security requirements standard specifying Level 1 (Opportunistic), Level 2 (Standard Enterprise), and Level 3 (Advanced/Critical Infrastructure) verification gates.
* **OWASP Mobile Application Security (MAS)**:
  * *MASVS (Mobile Application Security Verification Standard)*: Architectural standard for secure mobile apps.
  * *MASTG (Mobile Application Security Testing Guide)*: Technical testing runbook covering iOS and Android testing with Frida, Radare2, and JADX.
* **OWASP Top 10:2021**:
  * A01:2021-Broken Access Control
  * A02:2021-Cryptographic Failures
  * A03:2021-Injection
  * A04:2021-Insecure Design
  * A05:2021-Security Misconfiguration
  * A06:2021-Vulnerable and Outdated Components
  * A07:2021-Identification and Authentication Failures
  * A08:2021-Software and Data Integrity Failures
  * A09:2021-Security Logging and Monitoring Failures
  * A10:2021-Server-Side Request Forgery (SSRF)
* **OWASP API Security Top 10 (2023)**:
  * API1:2023-Broken Object Level Authorization (BOLA)
  * API2:2023-Broken Authentication
  * API3:2023-Broken Object Property Level Authorization
  * API4:2023-Unrestricted Resource Consumption
  * API5:2023-Broken Function Level Authorization (BFLA)
  * API6:2023-Unrestricted Access to Sensitive Business Flows
  * API7:2023-Server Side Request Forgery (SSRF)
  * API8:2023-Security Misconfiguration
  * API9:2023-Improper Inventory Management
  * API10:2023-Unsafe Consumption of APIs
* **OWASP Software Assurance Maturity Model (SAMM v2.0)**: Maturity evaluation model for organizational secure software development lifecycles (SSDLC).

---

## 5. MITRE & Scoring Standards

* **MITRE ATT&CK® Enterprise Matrix**: Globally accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations across 14 tactical phases.
* **MITRE CAPEC™ (Common Attack Pattern Enumeration and Classification)**: Catalog of common attack patterns employed by adversaries to exploit known weaknesses.
* **MITRE CWE™ (Common Weakness Enumeration)**: Formal dictionary of software weakness types; includes the annual *CWE Top 25 Most Dangerous Software Weaknesses*.
* **FIRST Common Vulnerability Scoring System (CVSS)**:
  * *CVSS v3.1 Specification Guide*: Metric definitions for Base, Temporal, and Environmental scores.
  * *CVSS v4.0 Specification Guide*: Enhanced metric groups introducing Threat Intelligence and Supplemental metrics.
* **FIRST Exploit Prediction Scoring System (EPSS)**: Data-driven probability model assessing the likelihood that a software vulnerability will be exploited in the wild within 30 days.

---

## 6. Foundational Computer Science & Security Research Papers

* **Aleph One (1996)**: *"Smashing the Stack for Fun and Profit"*, *Phrack Magazine*, Vol. 7, Issue 49. The foundational treatise detailing stack-based buffer overflows, memory layouts, and executable shellcode injection.
* **Solar Designer (1997)**: *"Getting around non-executable stack (and fix)"*, Bugtraq. Introduced the *return-to-libc* technique, laying the groundwork for modern code reuse without direct shellcode execution.
* **Hovav Shacham et al. (2007)**: *"The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)"*, Proceedings of the 14th ACM Conference on Computer and Communications Security (CCS). Formally established Return-Oriented Programming (ROP) using gadget chains ending in `ret` instructions.
* **Yoongu Kim et al. (2014)**: *"Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors"*, ACM/IEEE International Symposium on Computer Architecture (ISCA). First formal demonstration of the *Rowhammer* physical DRAM bit-flip vulnerability.
* **Paul Kocher et al. (2018)**: *"Spectre Attacks: Exploiting Speculative Execution"*, IEEE Symposium on Security and Privacy (S&P). Demonstrated how CPU branch predictors and speculative execution leak memory contents across hardware isolation boundaries via microarchitectural side-channels.
* **Moritz Lipp et al. (2018)**: *"Meltdown: Reading Kernel Memory from User Space"*, USENIX Security Symposium. Proved that out-of-order execution allows user-space processes to read arbitrary kernel memory.
* **James Kettle (2019)**: *"HTTP Desync Attacks: Request Smuggling in the Modern Era"*, Black Hat USA. Revitalized and formalized HTTP Request Smuggling methodologies across front-end reverse proxies and back-end microservices.
* **Orange Tsai (2017)**: *"A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages"*, Black Hat USA / DEF CON 25. Documented parser differential analysis between URL specification RFCs and standard language library implementations.

---

## 7. Cyber Law, Compliance & Evidentiary Forensics

* **United States Code**: *Computer Fraud and Abuse Act (CFAA)*, 18 U.S.C. § 1030. Governs intentional access to a protected computer without authorization or exceeding authorized access.
* **United Kingdom**: *Computer Misuse Act 1990 (CMA)*. Criminalizes unauthorized access to computer material, unauthorized access with intent to commit further offenses, and unauthorized acts with intent to impair computer operation.
* **Republic of India**: *Information Technology Act, 2000 (IT Act 2000)*:
  * *Section 43*: Penalty for damage to computer systems, unauthorized downloading, or extraction of data.
  * *Section 66*: Computer-related offenses involving fraud or dishonesty.
  * *Section 70*: Protected systems and critical information infrastructure protection.
* **European Union**: *General Data Protection Regulation (GDPR)*, Regulation (EU) 2016/679:
  * *Article 32*: Security of processing (mandates technical and organizational security measures).
  * *Article 33*: Notification of a personal data breach to the supervisory authority within 72 hours.
* **Payment Card Industry Security Standards Council**: *Payment Card Industry Data Security Standard (PCI-DSS v4.0)*:
  * *Requirement 6*: Develop and maintain secure systems and software.
  * *Requirement 11*: Regularly test security of systems and networks (mandates external/internal quarterly scans and annual penetration testing).
* **ISO/IEC 27037:2012**: *Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*. International standard for digital forensic chain of custody.
