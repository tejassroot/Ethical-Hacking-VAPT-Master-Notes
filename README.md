# Ethical Hacking & VAPT — Master Curriculum & Practical Reference Manual

[![Curriculum](https://img.shields.io/badge/Curriculum-12%20Volumes%20%7C%2034%20Modules-0284c7.svg)](#curriculum-architecture--module-index)
[![Lab Verification](https://img.shields.io/badge/Lab%20Test%20Suites-34%2F34%20Passing%20(100%25)-16a34a.svg)](#standalone-practical-lab-suites-1-to-1-module-parity)
[![Python](https://img.shields.io/badge/Python-3.8%2B%20(Zero%20pip%20deps)-eab308.svg)](#quickstart--lab-automation)
[![Standards](https://img.shields.io/badge/Standards-NIST%20%7C%20OWASP%20%7C%20PTES%20%7C%20MITRE-ea580c.svg)](#frameworks--standards-compliance)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](#license)

An exhaustive, production-grade cybersecurity compendium and automated diagnostic lab ecosystem comprising **12 Volumes**, **34 Modules**, **40 Compendia** (>140,000 words), and **34 Standalone Test Suites**. 

Engineered for security researchers, penetration testers, blue team defense engineers, and application security auditors, this repository bridges foundational computer science with enterprise-grade offensive and defensive security operations.

---

## Table of Contents

- [Executive Overview](#executive-overview)
- [Quickstart & Lab Automation](#quickstart--lab-automation)
  - [Make Commands](#make-commands)
  - [Cross-Platform Execution (Systems without Make)](#cross-platform-execution-systems-without-make)
- [Curriculum Architecture & Module Index](#curriculum-architecture--module-index)
- [Standalone Practical Lab Suites (1-to-1 Module Parity)](#standalone-practical-lab-suites-1-to-1-module-parity)
- [Docker Security Enclaves](#docker-security-enclaves)
- [The 20-Point Topic Schema Mandate](#the-20-point-topic-schema-mandate)
- [Frameworks & Standards Compliance](#frameworks--standards-compliance)
- [Operational Security & Responsible Testing](#operational-security--responsible-testing)
- [License](#license)

---

## Executive Overview

This curriculum is structured around an analytical, defensive-engineering discipline:
1. **Evidence-Based Auditing**: Replaces guesswork and indiscriminate scanning with systematic enumeration, hypothesis formulation, benign boundary verification, and verifiable proof-of-concept synthesis.
2. **Deterministic Lab Design**: Every primary module includes an automated, self-testing diagnostic tool written with **zero third-party package dependencies** (pure Python 3 standard library and POSIX Bash).
3. **Defense-in-Depth Remediation**: Every vulnerability classification pairs root-cause data-flow analysis with production-ready code fixes, framework-specific defenses, and system hardening benchmarks.

---

## Quickstart & Lab Automation

Anyone cloning this repository can immediately set up, audit, and run any of the 34 diagnostic lab suites using GNU `make` or the built-in Python runner.

```bash
# 1. Clone the repository
git clone https://github.com/tejassroot/Ethical-Hacking-VAPT-Master-Notes.git
cd Ethical-Hacking-VAPT-Master-Notes

# 2. Audit system prerequisites and configure permissions
make setup

# 3. View all available lab modules
make list

# 4. Execute a specific lab by module number (e.g., Module 30: OWASP Top 10)
make run MODULE=30

# 5. Run the full regression test sweep across all 34 labs
make test

# 6. Launch the interactive terminal menu
make interactive
```

### Make Commands

| Command | Description |
| :--- | :--- |
| `make help` | Displays the command manual, syntax examples, and descriptions |
| `make setup` | Audits host environment tools (`python3`, `bash`, `git`, `make`, `docker`) and ensures execute permissions |
| `make list` | Lists all 34 curriculum modules, titles, and lab script locations |
| `make test` | Runs the automated test harness across all 34 modules (reporting execution time and pass/fail summary) |
| `make run MODULE=<N>` | Runs a specific module lab directly (e.g., `make run MODULE=01`, `make run MODULE=30`) |
| `make interactive` | Launches an interactive terminal menu for selecting and running labs |
| `make docker-up` | Launches isolated Docker security testing enclaves (Alpine Diag, Juice Shop, DVWA, Nginx WAF, LocalStack) |
| `make docker-down` | Stops and tears down active Docker security enclaves |
| `make docker-status` | Inspects container status, port mappings, and running lab services |
| `make clean` | Removes Python bytecode caches (`__pycache__`, `*.pyc`) and temporary test artifacts |

### Cross-Platform Execution (Systems without Make)

For environments without GNU `make` installed (e.g., standard Windows PowerShell or bare environments), the standalone Python manager provides identical functionality:

```bash
# Audit host tools
python3 scripts/lab_runner.py --check-env

# List modules
python3 scripts/lab_runner.py --list

# Run specific module
python3 scripts/lab_runner.py --run 30

# Run full regression suite
python3 scripts/lab_runner.py --test-all

# Launch interactive menu
python3 scripts/lab_runner.py --interactive
```

---

## Curriculum Architecture & Module Index

The master curriculum spans 12 structured volumes covering every operational phase of offensive and defensive security engineering:

### Volume 01: Computer & Programming Foundations
- [Module 01: Computer Hardware, OS Architecture & Productivity Systems](./Volume_01_Computer_and_Programming_Foundations/Module_01_Computer_Hardware_OS_and_Productivity.md) — CPU microarchitectures, memory hierarchy, system calls, OS kernel/user-space mechanics, and malicious document macro structures.
- [Module 02: Advanced Programming, Fullstack Architecture & Secure SDLC](./Volume_01_Computer_and_Programming_Foundations/Module_02_Advanced_Programming_and_Secure_Development.md) — Multi-tier software architecture, secure SDLC integration, STRIDE threat modeling, and SAST taint-flow analysis.

### Volume 02: Linux, Networking & Security Foundations
- [Module 04: Operating System Installation & Virtual Lab Architecture](./Volume_02_Linux_Networking_and_Security_Foundations/Module_04_OS_Installation_and_Virtual_Lab_Arch.md) — Hypervisors (Type-1/Type-2), isolated virtual network topologies, multi-NIC pivot architectures, and Kali Linux tuning.
- [Module 05: Linux Architecture, System Administration & Privilege Isolation](./Volume_02_Linux_Networking_and_Security_Foundations/Module_05_Linux_Architecture_and_Administration.md) — Linux directory hierarchy, systemd, process namespaces, SUID/SGID auditing, and shell automation.
- [Module 08: Networking Protocols, Traffic Analysis & Boundary Defense](./Volume_02_Linux_Networking_and_Security_Foundations/Module_08_Networking_Protocols_and_Security.md) — OSI and TCP/IP protocol stacks, IPv4/IPv6 headers, TCP three-way handshake state machines, Wireshark packet dissection, and stateful firewalls.
- [Module 24: Applied Cryptography, PKI Infrastructure & Secret Management](./Volume_02_Linux_Networking_and_Security_Foundations/Module_24_Applied_Cryptography_and_PKI.md) — Symmetric/asymmetric ciphers (AES-GCM, RSA, ECC), secure hashing algorithms, X.509 certificate chains, TLS 1.3 handshakes, and PKI validation.

### Volume 03: Reconnaissance, OSINT & Enumeration
- [Module 06: Information Gathering, Passive Reconnaissance & OSINT](./Volume_03_Reconnaissance_OSINT_and_Enumeration/Module_06_Information_Gathering_and_Footprinting.md) — Open-source intelligence (OSINT), DNS zone transfers, WHOIS auditing, Certificate Transparency (CT) log mining, and Shodan queries.
- [Module 07: Enumeration Methodology & Active Service Auditing](./Volume_03_Reconnaissance_OSINT_and_Enumeration/Module_07_Enumeration_Methodology.md) — Active port scanning, banner grabbing, SMB dialect negotiation, RPC endpoint mapping, and SNMP MIB walking.
- [Module 28: Web Surface Mapping, Asset Discovery & Endpoint Extraction](./Volume_03_Reconnaissance_OSINT_and_Enumeration/Module_28_Web_Information_Gathering_Surface_Mapping.md) — Web application fingerprinting, DOM parsing, client-side JavaScript asset extraction, and hidden API route mining.

### Volume 04: Core Ethical Hacking
- [Module 03: Introduction to Ethical Hacking, Legal Boundaries & RoE](./Volume_04_Core_Ethical_Hacking/Module_03_Introduction_to_Ethical_Hacking.md) — Legal frameworks (CFAA, IT Act, GDPR), Rules of Engagement (RoE), CIDR scope guardrails, and vulnerability triage.
- [Module 09: Anonymity, Privacy Engineering & Operational Security (OpSec)](./Volume_04_Core_Ethical_Hacking/Module_09_Anonymity_Privacy_and_OpSec.md) — Tor onion routing mechanics, multi-hop VPN chains, DNS/WebRTC leak auditing, and operational identity isolation.
- [Module 10: Password Security, Cryptographic Hashes & Credential Auditing](./Volume_04_Core_Ethical_Hacking/Module_10_Password_Security_and_Credential_Auditing.md) — Key derivation functions (PBKDF2, bcrypt, scrypt, Argon2), password entropy, rainbow tables, Hashcat rule synthesis, and passkey architecture.
- [Module 11: Layer 2 Attacks, Packet Sniffing & Switch Security Defense](./Volume_04_Core_Ethical_Hacking/Module_11_Sniffing_Spoofing_and_Layer2_Defense.md) — ARP cache poisoning, MAC table flooding, Dynamic ARP Inspection (DAI), DHCP snooping, and switch port security.
- [Module 12: Social Engineering, Psychological Lures & Human Risk Assessment](./Volume_04_Core_Ethical_Hacking/Module_12_Social_Engineering_Human_Risk_Assessment.md) — Psychological influence vectors (Cialdini heuristics), pretext formulation, authorization verification, and security awareness programs.

### Volume 05: Web Security Foundations
- [Module 21: Web Application Architecture, Protocols & Browser Security](./Volume_05_Web_Security_Foundations/Module_21_Web_Security_Foundations.md) — HTTP/1.1, HTTP/2, HTTP/3, Same-Origin Policy (SOP), Cross-Origin Resource Sharing (CORS), secure cookie attributes, and DOM contexts.
- [Module 29: Web Application Security Testing Tools & Interception Proxies](./Volume_05_Web_Security_Foundations/Module_29_Web_Application_Security_Tools.md) — Interception proxy architecture (Burp Suite Pro, OWASP ZAP, Caido), parameter fuzzing engines (ffuf), upstream proxy chaining, and custom matchers.

### Volume 06: Web Application VAPT
- [Module 30: OWASP Top 10 Vulnerabilities, Root Causes & Remediation](./Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md) — Exhaustive analysis of Broken Access Control, SQL Injection, SSRF, Cross-Site Scripting (XSS), Insecure Deserialization, SSTI, and cryptographic failures.
- [Module 31: Web VAPT Reporting, Proof-of-Concept & Defect Documentation](./Volume_06_Web_Application_VAPT/Module_31_Web_VAPT_Reporting_and_Documentation.md) — Vulnerability scoring (CVSS v3.1 and v4.0), CWE mapping, reproduction step formulation, and executive/technical report generation.

### Volume 07: Network Penetration Testing
- [Module 26: Penetration Testing Methodologies & Standards](./Volume_07_Network_Penetration_Testing/Module_26_Penetration_Testing_Fundamentals.md) — PTES, NIST SP 800-115, OSSTMM execution lifecycles, and black-box, gray-box, and white-box test postures.
- [Module 27: Hands-On Network Penetration Testing Lab Architecture](./Volume_07_Network_Penetration_Testing/Module_27_Hands_on_Lab_Architecture.md) — Multi-tier virtualized test networks, DMZ segmentation, vulnerable target enclaves, and strict isolation controls.
- [Module 32: Network Penetration Testing Execution & Host Auditing](./Volume_07_Network_Penetration_Testing/Module_32_Network_Penetration_Testing_Execution.md) — Port discovery, service auditing, SMB signing verification, relay boundary testing, and network pivot simulations.

### Volume 08: API Security
- [Module 33: API Security Testing, Microservices & Modern Web Architectures](./Volume_08_API_Security/Module_33_API_Testing_and_Microservice_Security.md) — REST, GraphQL, gRPC, OAuth2/OIDC auditing, Broken Object Level Authorization (BOLA), Mass Assignment, and JWT algorithm manipulation.

### Volume 09: Mobile & Android Security
- [Module 17: Mobile Application Security Foundations & Architecture](./Volume_09_Mobile_and_Android_Security/Module_17_Mobile_Security_Foundations.md) — Android security architecture, Linux kernel sandboxing, Binder IPC, application permissions, and secure local storage.
- [Module 34: Android Application VAPT, Reverse Engineering & Dynamic Hooks](./Volume_09_Mobile_and_Android_Security/Module_34_Android_App_VAPT_and_Reverse_Engineering.md) — APK decompilation, Smali bytecode analysis, JADX deobfuscation, ADB debugging, and dynamic instrumentation using Frida.

### Volume 10: Advanced Security Disciplines
- [Module 13: Wireless Security, 802.11 Protocols & Enterprise Defense](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_13_Wireless_Security.md) — 802.11 frame structures, WPA2/WPA3 4-way handshakes, PMKID analysis, rogue AP detection, and 802.11w Protected Management Frames.
- [Module 14: System Security, Operating System Hardening & Host Defense](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_14_System_Security_and_Host_Defense.md) — Windows & Linux internal security models, CWE-428 unquoted service paths, Registry Run keys, Sysmon telemetry, and EDR mechanics.
- [Module 15: Phishing Infrastructure Analysis, Authentication & Defense](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_15_Phishing_Architecture_and_Email_Security.md) — Email delivery mechanisms, SPF, DKIM, DMARC, ARC protocols, and Adversary-in-the-Middle (AiTM) reverse proxies.
- [Module 16: Malware Analysis Foundations & Reverse Engineering](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_16_Malware_Analysis_Foundations.md) — PE and ELF file formats, section entropy analysis, static import hashing (`imphash`), dynamic sandboxing, and YARA signature compilation.
- [Module 18: Defensive Technologies, SIEM Architecture & Detection Engineering](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_18_Defense_Technology_and_SIEM.md) — NIDS/NIPS (Snort, Suricata), SIEM pipeline architecture, Sigma detection rule compilation, and Risk-Based Alerting (RBA).
- [Module 19: Email Security Protocols & Header Forensics](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_19_Email_Security_Protocols_Header_Forensics.md) — Chronological `Received:` header hop forensics, forged gateway boundaries, SPF/DKIM verification, and forensic artifact extraction.
- [Module 20: Denial of Service, Distributed DoS & Mitigation Architectures](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_20_Common_Attacks_and_DoS_Mitigation.md) — L4 amplification mechanisms (DNS, NTP), SYN flood mitigation (RFC 4987 SYN cookies), ReDoS algorithmic complexity, and Token Bucket rate limiting.
- [Module 22: Internet of Things (IoT) & Embedded Device Security](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_22_Internet_of_Things_Embedded_Security.md) — IoT hardware interfaces (UART, JTAG, SPI), firmware unpacking with Binwalk, SquashFS extraction, and hardcoded credential discovery.
- [Module 23: Steganography & Digital Media Forensics](./Volume_10_Malware_Wireless_IoT_and_Advanced_Security/Module_23_Steganography_and_Digital_Forensics.md) — Spatial domain LSB steganography in BMP/PNG, transform domain techniques, Chi-Square statistical detection, and file carving.

### Volume 11: Reporting Methodology & Professional Practice
- [Module 25: Cyber Laws, Incident Response Compliance & Evidence Handling](./Volume_11_Reporting_Methodology_and_Professional_Practice/Module_25_Cyber_Laws_Crime_and_Compliance.md) — Computer fraud statutes, GDPR/HIPAA compliance, digital evidence preservation, and cryptographic chain-of-custody ledgers.
- [Enterprise VAPT Execution Workflow](./Volume_11_Reporting_Methodology_and_Professional_Practice/Enterprise_VAPT_Execution_Workflow.md) — End-to-end commercial engagement lifecycle: pre-engagement scoping, testing execution, vulnerability triage, and remediation retesting.
- [Bug Bounty Hunting Methodology](./Volume_11_Reporting_Methodology_and_Professional_Practice/Bug_Bounty_Hunting_Methodology.md) — Program reconnaissance, asset surface expansion, high-signal reporting, and triager communication guidelines.

### Volume 12: Reference Material, Checklists & Blueprints
- [Master Lab Blueprints](./Volume_12_Labs_Exercises_Checklists_and_Reference_Material/Master_Lab_Blueprints.md) — Turnkey multi-tier Docker and Vagrant enclave specifications (Levels 1 through 5).
- [Master VAPT Checklists](./Volume_12_Labs_Exercises_Checklists_and_Reference_Material/Master_VAPT_Checklists.md) — Comprehensive assessment checklists covering Web, API, Network, Active Directory, and Mobile scopes.
- [Career Roadmap & Interview Mastery](./Volume_12_Labs_Exercises_Checklists_and_Reference_Material/Career_Roadmap_and_Interview_Mastery.md) — Structured technical career progression from Junior Pentester to Staff Security Engineer, with scenario-based interview guides.
- [Authoritative References Library](./Volume_12_Labs_Exercises_Checklists_and_Reference_Material/Authoritative_References_Library.md) — Citations spanning IETF RFCs, NIST Special Publications, OWASP methodologies, and academic security literature.

---

## Standalone Practical Lab Suites (1-to-1 Module Parity)

Every module from 01 through 34 includes a standalone diagnostic script in [`labs/`](./labs). All scripts execute locally with zero external dependencies and run built-in deterministic verification suites:

| Module | Diagnostic Lab Script | Focus Area & Capabilities | Test Status |
| :---: | :--- | :--- | :---: |
| **01** | [`labs/module_01/hardware_os_security_auditor.py`](./labs/module_01/hardware_os_security_auditor.py) | CPU flags (`NX`, `SMEP`, `SMAP`, `KPTI`) & Linux ASLR memory randomization | `PASS` |
| **02** | [`labs/module_02/secure_sdlc_threat_modeler.py`](./labs/module_02/secure_sdlc_threat_modeler.py) | STRIDE threat modeling, DREAD risk scoring & SAST taint-flow analysis | `PASS` |
| **03** | [`labs/module_03/scope_enforcement_guard.py`](./labs/module_03/scope_enforcement_guard.py) | Scoping guardrails, CIDR boundary validation & target containment | `PASS` |
| **04** | [`labs/module_04/virtual_lab_topology_checker.py`](./labs/module_04/virtual_lab_topology_checker.py) | Multi-NIC pivot topologies, RFC 1918 compliance & Docker privilege audits | `PASS` |
| **05** | [`labs/module_05/linux_security_audit.sh`](./labs/module_05/linux_security_audit.sh) | Linux kernel, SUID/SGID auditing, world-writable files & privilege escalation | `PASS` |
| **06** | [`labs/module_06/osint_footprint_engine.py`](./labs/module_06/osint_footprint_engine.py) | Passive OSINT footprinting, Certificate Transparency mining & WHOIS parsing | `PASS` |
| **07** | [`labs/module_07/service_enumeration_auditor.py`](./labs/module_07/service_enumeration_auditor.py) | Service enumeration, banner grabbing, SMB dialects & RPC port mapping | `PASS` |
| **08** | [`labs/module_08/network_packet_dissector.py`](./labs/module_08/network_packet_dissector.py) | Raw socket IPv4, TCP (3-way handshake flags) & UDP dissector with checksums | `PASS` |
| **09** | [`labs/module_09/anonymity_leak_auditor.py`](./labs/module_09/anonymity_leak_auditor.py) | Tor circuit integrity, DNS leak detection, WebRTC STUN & IPv6 leakage | `PASS` |
| **10** | [`labs/module_10/credential_security_auditor.py`](./labs/module_10/credential_security_auditor.py) | KDF work factors (`PBKDF2`/`Argon2`/`bcrypt`), Shannon entropy & policy checks | `PASS` |
| **11** | [`labs/module_11/layer2_security_auditor.py`](./labs/module_11/layer2_security_auditor.py) | ARP spoofing detection, Dynamic ARP Inspection (DAI) & MAC exhaustion | `PASS` |
| **12** | [`labs/module_12/human_risk_evaluator.py`](./labs/module_12/human_risk_evaluator.py) | Psychological pretext analyzer, Cialdini heuristics & phishing metrics | `PASS` |
| **13** | [`labs/module_13/wireless_security_auditor.py`](./labs/module_13/wireless_security_auditor.py) | 802.11 frame parser, WPA2 handshake PMK synthesizer, PMKID & 802.11w | `PASS` |
| **14** | [`labs/module_14/host_defense_auditor.py`](./labs/module_14/host_defense_auditor.py) | CWE-428 unquoted paths, Windows Run/RunOnce ASEP keys & Sysmon logs | `PASS` |
| **15** | [`labs/module_15/phishing_analysis_engine.py`](./labs/module_15/phishing_analysis_engine.py) | RFC 5321/5322 header alignment, SPF DNS tree, DKIM & AiTM proxy detection | `PASS` |
| **16** | [`labs/module_16/malware_analysis_engine.py`](./labs/module_16/malware_analysis_engine.py) | PE/ELF section entropy, import hashing (`imphash`) & YARA rule pattern engine | `PASS` |
| **17** | [`labs/module_17/android_storage_and_manifest_auditor.py`](./labs/module_17/android_storage_and_manifest_auditor.py) | `AndroidManifest.xml` parser (exported components) & SQLite storage auditor | `PASS` |
| **18** | [`labs/module_18/siem_detection_engine.py`](./labs/module_18/siem_detection_engine.py) | Sigma rule parser, Splunk/Elastic query translator & Risk-Based Alerting | `PASS` |
| **19** | [`labs/module_19/audit_email_headers.py`](./labs/module_19/audit_email_headers.py) | Chronological `Received:` hop parser, spoofed boundaries & DMARC analyzer | `PASS` |
| **20** | [`labs/module_20/dos_mitigation_engine.py`](./labs/module_20/dos_mitigation_engine.py) | UDP amplification factor, RFC 4987 SYN cookies, ReDoS checks & Token Bucket | `PASS` |
| **21** | [`labs/module_21/cors_header_auditor.py`](./labs/module_21/cors_header_auditor.py) | Same-Origin Policy (SOP), CORS misconfigurations & security headers | `PASS` |
| **22** | [`labs/module_22/audit_iot_firmware.py`](./labs/module_22/audit_iot_firmware.py) | Binwalk header signatures, SquashFS entropy & hardcoded credentials | `PASS` |
| **23** | [`labs/module_23/stego_forensics_lab.py`](./labs/module_23/stego_forensics_lab.py) | 24-bit BMP & PNG LSB steganography injector, extractor & Chi-Square detector | `PASS` |
| **24** | [`labs/module_24/pki_crypto_audit.py`](./labs/module_24/pki_crypto_audit.py) | Cipher suite auditor, RSA/ECC generator, X.509 chain verifier & CRL check | `PASS` |
| **25** | [`labs/module_25/evidence_custody_verifier.py`](./labs/module_25/evidence_custody_verifier.py) | Cryptographic chain-of-custody ledger with SHA-256 block-hashing | `PASS` |
| **26** | [`labs/module_26/evidence_chain_of_custody_sealer.py`](./labs/module_26/evidence_chain_of_custody_sealer.py) | Dual-hash (SHA-256 + SHA-512) evidence sealing adhering to ISO/IEC 27037 | `PASS` |
| **27** | [`labs/module_27/network_containment_auditor.py`](./labs/module_27/network_containment_auditor.py) | Multi-subnet boundary validation, routing tables & egress containment | `PASS` |
| **28** | [`labs/module_28/web_surface_mapper.py`](./labs/module_28/web_surface_mapper.py) | HTML/DOM parser, tech stack fingerprinting & JavaScript API endpoint discovery | `PASS` |
| **29** | [`labs/module_29/fuzz_and_proxy_engine.py`](./labs/module_29/fuzz_and_proxy_engine.py) | Multi-threaded HTTP fuzzing, wordlist mutation & Burp upstream proxy adapter | `PASS` |
| **30** | [`labs/module_30/owasp_top10_lab.py`](./labs/module_30/owasp_top10_lab.py) | OWASP Top 10 lab: SQLi, XSS, IDOR, SSRF, SSTI, Mass Assignment & Defenses | `PASS` |
| **31** | [`labs/module_31/vapt_report_and_cvss_engine.py`](./labs/module_31/vapt_report_and_cvss_engine.py) | CVSS v3.1/v4.0 vector scoring calculator & structured Markdown report compiler | `PASS` |
| **32** | [`labs/module_32/service_audit_and_pivot_engine.py`](./labs/module_32/service_audit_and_pivot_engine.py) | Network pivot simulation, SMB signing auditor, anonymous FTP & relay testing | `PASS` |
| **33** | [`labs/module_33/api_security_testing_engine.py`](./labs/module_33/api_security_testing_engine.py) | JWT algorithm manipulation (`alg: none`), Mass Assignment & GraphQL depth | `PASS` |
| **34** | [`labs/module_34/apk_reversing_and_frida_engine.py`](./labs/module_34/apk_reversing_and_frida_engine.py) | Smali bytecode inverter, API secret scanner & dynamic Frida hook synthesizer | `PASS` |

---

## Docker Security Enclaves

For live service penetration testing and container security experimentation, pre-configured compose files are located in the [`docker/`](./docker) directory:

| Enclave | Compose Configuration | Included Services |
| :--- | :--- | :--- |
| **Level 1** | [`docker/docker-compose.level1.yml`](./docker/docker-compose.level1.yml) | Alpine Diagnostic Box (`nmap`, `tcpdump`, `dig`, `socat`, `scapy`, `python3`) |
| **Level 2** | [`docker/docker-compose.level2.yml`](./docker/docker-compose.level2.yml) | OWASP Juice Shop (SPA/API), DVWA (Classic Web), MariaDB Relational Backend |
| **Level 3** | [`docker/docker-compose.level3.yml`](./docker/docker-compose.level3.yml) | Nginx DMZ Reverse Proxy & WAF, Internal Backend Service, Suricata NIDS Sensor |
| **Level 5** | [`docker/docker-compose.level5.yml`](./docker/docker-compose.level5.yml) | LocalStack (AWS S3/IAM/Lambda Emulation), MinIO S3 Object Storage Service |

To spin up or inspect any enclave:
```bash
make docker-up       # Starts all enclaves
make docker-status   # Checks active container ports
make docker-down     # Shuts down enclaves cleanly
```

---

## The 20-Point Topic Schema Mandate

To maintain consistent depth across the entire curriculum, every primary module adheres strictly to an authoritative 20-point analytical structure:

1. **Learning Objectives**: Concrete, measurable skills acquired.
2. **Prerequisites**: Conceptual and technical foundation required before study.
3. **What Is It?**: Clear, conceptual explanation accessible to newcomers.
4. **Technical Explanation**: Deep architectural mechanics, memory layout, system calls, or protocol design.
5. **How It Works**: Step-by-step state machines, ASCII/Mermaid protocol sequences, data flows.
6. **Security Perspective**: Attack surface analysis, trust boundaries, threat actors, and abuse cases.
7. **Auditing Methodology**: Professional verification workflow: *Recon → Enumeration → Mapping → Hypothesis → Benign Testing → Evidence Collection → Impact Assessment → Remediation*.
8. **Tooling Deep-Dive**: In-depth inspection of key diagnostic utilities (CLI syntax, flag mechanics, safe lab usage).
9. **Practical Lab Setup**: Reproducible, isolated lab configurations using Docker or virtualized networks.
10. **Evidence & Verification**: Eliminating false positives, validating boundary reactions, establishing deterministic proof.
11. **Telemetry & Detection**: Log analysis, SIEM signatures, Suricata/Snort/Sigma rules, host artifacts.
12. **Mitigation**: Production-ready code patches, robust configuration snippets, defense-in-depth measures.
13. **Hardening**: System and protocol hardening guides aligned with CIS Benchmarks and NIST SP 800-53.
14. **Documented Case Studies**: Analysis of historical, documented vulnerabilities, root-cause mechanisms, and lessons learned.
15. **Common Mistakes & Anti-Patterns**: Pitfalls made by novice practitioners and defensive architects.
16. **Professional vs. Naive Methodology**: Contrast between automated scanner reliance and manual security verification.
17. **Knowledge Check & Interview Questions**: Graded questions (Beginner, Intermediate, Advanced, Scenario).
18. **Progressive Practice Exercises**: Hands-on challenges designed for skill reinforcement.
19. **Key Takeaways**: High-density summary of core tenets.
20. **Authoritative References**: Primary literature, RFCs, NIST SP, OWASP documents, vendor specifications.

---

## Frameworks & Standards Compliance

The analytical methodologies, lab structures, and checklists across this repository directly align with industry standards:
- **NIST Special Publications**: NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*), NIST SP 800-53 Rev. 5, NIST SP 800-30.
- **OWASP Foundations**: OWASP Web Security Testing Guide (WSTG v4.2), Application Security Verification Standard (ASVS v4.0.3), Mobile Application Security Verification Standard (MASVS), and API Security Top 10.
- **Penetration Testing Execution Standard (PTES)**: Full phase coverage from Pre-engagement Interactions to Post-exploitation and Reporting.
- **MITRE ATT&CK Framework**: Enterprise and Cloud tactics, techniques, and procedures (TTPs).
- **IETF RFC Standards**: Core internet protocols (RFC 791 IPv4, RFC 793 TCP, RFC 9110 HTTP, RFC 5246/8446 TLS, RFC 5321/5322 Email).

---

## Operational Security & Responsible Testing

1. **Secret Masking & Redaction**: In accordance with operational security standards, all sample tokens, API keys, and session hashes are redacted to their first 4 characters followed by masking (e.g., `sk_live_1234****REDACTED`).
2. **Benign Boundary Verification**: All test probes in the lab suites use non-destructive indicators (e.g., mathematical evaluation proofs, loopback listeners, console log triggers) rather than intrusive payloads.
3. **Strict Scoping**: Testing must strictly remain within authorized target environments, virtualized isolated networks, and designated container enclaves.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).  
Authored by **Tejas** ([@tejassroot](https://github.com/tejassroot)).
