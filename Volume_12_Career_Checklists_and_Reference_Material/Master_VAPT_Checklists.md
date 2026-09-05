# Volume 12: Career Roadmap, Checklists & Reference Material
# Master VAPT Checklists: Enterprise Web, Network, Active Directory, API & Mobile

---

## 1. Overview & Operational Methodology

This master checklist repository serves as the unified operational standard for technical security assessments, vulnerability assessments, and penetration testing (VAPT) across enterprise environments. 

Every audit task is structured to ensure:
1. **Repeatability**: Standardized execution aligned with global frameworks (OWASP WSTG v4.2, OWASP ASVS v4.0, NIST SP 800-115, PTES, OWASP API Top 10 2023, and OWASP MASVS v2.0).
2. **Defensible Verification**: Non-destructive boundary validation eliminating speculative or automated false positives.
3. **Traceable Evidence**: Structured logging of HTTP requests/responses, socket connections, packet traces, and host artifacts without exposing unmasked customer secrets.

---

## 2. Web Application VAPT Checklist (OWASP WSTG v4.2 Aligned)

```
========================================================================================================================
CHECKLIST SECTION 1: INFORMATION GATHERING & CONFIGURATION (WSTG-INFO & WSTG-CONF)
========================================================================================================================
[ ] WSTG-INFO-01: Conduct search engine discovery, reconnaissance, and Google Dorking for exposed indexes.
[ ] WSTG-INFO-02: Fingerprint web server software, OS, and reverse proxy layers via Server and X-Powered-By headers.
[ ] WSTG-INFO-03: Review web server meta-files (`robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`).
[ ] WSTG-INFO-04: Enumerate application sub-domains, staging tiers, and developer environments.
[ ] WSTG-INFO-05: Review public code repositories (GitHub, GitLab) for leaked organization secrets and endpoints.
[ ] WSTG-INFO-06: Identify application entry points, URL parameters, REST/SOAP endpoints, and query parameters.
[ ] WSTG-INFO-07: Map execution paths and technological dependencies (Angular, React, Vue, jQuery, Spring, Laravel).
[ ] WSTG-CONF-01: Audit network and infrastructure configuration, default ports, and exposed administrative services.
[ ] WSTG-CONF-02: Audit application platform configuration (debug mode disablement, detailed error masking).
[ ] WSTG-CONF-03: Verify file extension handling and prevent raw execution of uploaded script extensions.
[ ] WSTG-CONF-04: Audit backup and unreferenced files (`.bak`, `.old`, `.swp`, `.env`, `.git/`, `.DS_Store`).
[ ] WSTG-CONF-05: Enumerate administrative and sensitive interfaces (`/admin`, `/actuator`, `/swagger`, `/graphql`).
[ ] WSTG-CONF-06: Audit HTTP methods (verify dangerous methods `PUT`, `DELETE`, `TRACE`, `CONNECT` are restricted).
[ ] WSTG-CONF-07: Verify HTTP Strict Transport Security (HSTS) with `includeSubDomains` and `preload`.
[ ] WSTG-CONF-08: Test Cross-Origin Resource Sharing (CORS) policies for wildcard `*` with credentials or origin reflection.

========================================================================================================================
CHECKLIST SECTION 2: IDENTITY, AUTHENTICATION & ACCESS CONTROL (WSTG-IDNT, WSTG-AUTH & WSTG-ATHZ)
========================================================================================================================
[ ] WSTG-IDNT-01: Audit role definitions and ensure segregation of duties across distinct tenant roles.
[ ] WSTG-IDNT-02: Test user registration process for duplicate identities or automatic privilege elevation.
[ ] WSTG-IDNT-03: Audit account provisioning and de-provisioning workflows for orphan active accounts.
[ ] WSTG-IDNT-04: Check account harvesting and user enumeration via error message differentials and response timings.
[ ] WSTG-AUTH-01: Verify credentials transport over TLS 1.2+ exclusively without query string exposure.
[ ] WSTG-AUTH-02: Test for default credentials across vendor software, DBMS consoles, and administrative consoles.
[ ] WSTG-AUTH-03: Test account lockout mechanisms and rate limiting against automated brute-force attacks.
[ ] WSTG-AUTH-04: Audit authentication bypass mechanisms (parameter tampering, SQLi in login, forced browsing).
[ ] WSTG-AUTH-05: Test "Remember Me" functionality for static tokens or insecure cookie derivation.
[ ] WSTG-AUTH-06: Audit password reset workflows (token entropy, token expiration, single-use invalidation).
[ ] WSTG-AUTH-07: Test Multi-Factor Authentication (MFA) enforcement (endpoint skipping, code brute force, response tampering).
[ ] WSTG-ATHZ-01: Test for Path Traversal / Arbitrary File Read (`../../etc/passwd`, absolute path injection).
[ ] WSTG-ATHZ-02: Test for Broken Object-Level Authorization (BOLA/IDOR) on database keys and GUIDs across tenants.
[ ] WSTG-ATHZ-03: Test for Vertical Privilege Escalation (Standard User accessing Administrator functions).
[ ] WSTG-ATHZ-04: Test for Horizontal Privilege Escalation (Tenant A accessing Tenant B customer data).
[ ] WSTG-ATHZ-05: Test for Insecure Direct Object References in administrative APIs and export routines.

========================================================================================================================
CHECKLIST SECTION 3: SESSION MANAGEMENT (WSTG-SESS)
========================================================================================================================
[ ] WSTG-SESS-01: Audit cookie security attributes: `Secure`, `HttpOnly`, `SameSite=Lax/Strict`.
[ ] WSTG-SESS-02: Test session token entropy, randomness, and length (minimum 128 bits cryptographic randomness).
[ ] WSTG-SESS-03: Test for Session Fixation (verify session token regeneration immediately upon successful authentication).
[ ] WSTG-SESS-04: Test for Session Invalidation on Logout (verify server-side session termination in Redis/database).
[ ] WSTG-SESS-05: Test idle session timeout and absolute session expiration.
[ ] WSTG-SESS-06: Test Cross-Site Request Forgery (CSRF) defenses (anti-CSRF tokens, SameSite cookies, custom headers).
[ ] WSTG-SESS-07: Test session puzzling and variable overloading across multi-step wizard flows.

========================================================================================================================
CHECKLIST SECTION 4: INPUT VALIDATION & INJECTION (WSTG-INP)
========================================================================================================================
[ ] WSTG-INP-01: Test for Reflected Cross-Site Scripting (XSS) with benign boundary probes (`"><xss>`).
[ ] WSTG-INP-02: Test for Stored Cross-Site Scripting (XSS) in user profiles, comments, tickets, and logs.
[ ] WSTG-INP-03: Test for DOM-based XSS via source-to-sink data flow (`location.hash`, `innerHTML`, `document.write`).
[ ] WSTG-INP-04: Test for SQL Injection (In-Band UNION, Boolean-based Blind, Time-based Blind) with parameterized checks.
[ ] WSTG-INP-05: Test for LDAP Injection in directory query fields.
[ ] WSTG-INP-06: Test for Server-Side Request Forgery (SSRF) against internal metadata (`169.254.169.254`, loopback).
[ ] WSTG-INP-07: Test for XML External Entity (XXE) Injection in XML parsers and document upload engines.
[ ] WSTG-INP-08: Test for OS Command Injection (`|`, `&`, `;`, `$()`) using non-destructive sleep probes.
[ ] WSTG-INP-09: Test for Server-Side Template Injection (SSTI) in Jinja2, Thymeleaf, Freemarker using `{{7*7}}`.
[ ] WSTG-INP-10: Test for Unrestricted File Upload (extension validation, MIME verification, execution restriction).
[ ] WSTG-INP-11: Test for Host Header Injection and Password Reset Poisoning.
[ ] WSTG-INP-12: Test for HTTP Request Smuggling (CL.TE, TE.CL, TE.TE parser differentials).

========================================================================================================================
CHECKLIST SECTION 5: ERROR HANDLING, CRYPTO & BUSINESS LOGIC (WSTG-ERR, CRYP, BUSA, CLNT)
========================================================================================================================
[ ] WSTG-ERR-01: Audit server error handling (ensure stack traces, database schema, and path details are masked).
[ ] WSTG-ERR-02: Review generic error codes and confirm absence of sensitive variable leakage.
[ ] WSTG-CRYP-01: Audit TLS protocol configuration (enforce TLS 1.2 and 1.3; disable SSLv2, SSLv3, TLS 1.0, TLS 1.1).
[ ] WSTG-CRYP-02: Audit cipher suites (enforce AEAD suites: AES-GCM, CHACHA20-POLY1305; disable CBC and RC4).
[ ] WSTG-CRYP-03: Audit cryptographic storage of passwords (verify Argon2id, PBKDF2, or bcrypt).
[ ] WSTG-BUSA-01: Test business logic data validation (negative numbers, quantity overflows, price tampering).
[ ] WSTG-BUSA-02: Test business workflow bypass (skipping payment verification steps, out-of-order state transitions).
[ ] WSTG-BUSA-03: Test concurrency and race conditions on financial transfers, coupon redemptions, and limits.
[ ] WSTG-BUSA-04: Test application rate limits against automated scraping, high-frequency actions, and resource exhaustion.
[ ] WSTG-CLNT-01: Audit Content Security Policy (CSP Level 3) directives and test for unsafe-inline / unsafe-eval.
[ ] WSTG-CLNT-02: Test for Clickjacking / UI Redressing (`X-Frame-Options: DENY` or `frame-ancestors 'none'`).
[ ] WSTG-CLNT-03: Audit HTML5 Web Messaging (`window.postMessage`) for wildcards (`*`) and missing origin checks.
```

---

## 3. Network Infrastructure & Active Directory Assessment Checklist

```
========================================================================================================================
CHECKLIST SECTION 1: EXTERNAL NETWORK PERIMETER & BORDER ROUTING
========================================================================================================================
[ ] NET-EXT-01: Port scan target perimeter range (/24 to /32) using SYN scanning across all 65,535 TCP ports.
[ ] NET-EXT-02: UDP top-ports scan (DNS, SNMP, NTP, IKE/IPsec, OpenVPN) to identify stateless listening services.
[ ] NET-EXT-03: Validate perimeter firewall rule integrity (verify non-public services SSH, RDP, SMB, DB are blocked).
[ ] NET-EXT-04: Audit external remote access solutions (VPN gateways, Citrix, RD Gateway, Pulse Secure, GlobalProtect).
[ ] NET-EXT-05: Enforce Multi-Factor Authentication (MFA) with FIDO2 or push notification on all public ingress points.
[ ] NET-EXT-06: Audit TLS certificates across all external endpoints for expiration, weak key lengths (<2048-bit), and SNI.
[ ] NET-EXT-07: Test for open DNS resolvers and verify DNS zone transfer restrictions (AXFR).
[ ] NET-EXT-08: Audit email authentication records (SPF syntax, DKIM keys, DMARC `p=reject`, MTA-STS).

========================================================================================================================
CHECKLIST SECTION 2: INTERNAL NETWORK SEGMENTATION & LAYER-2 DEFENSES
========================================================================================================================
[ ] NET-INT-01: Verify Layer-2 isolation (test VLAN hopping, Double Tagging 802.1Q, and switch spoofing).
[ ] NET-INT-02: Audit ARP spoofing defenses (verify Dynamic ARP Inspection [DAI] and DHCP Snooping are enabled).
[ ] NET-INT-03: Test for rogue DHCP servers and verify DHCP Snooping untrusted port drops.
[ ] NET-INT-04: Audit switch port security (verify MAC address limits and violation shutdown actions).
[ ] NET-INT-05: Test internal broadcast name resolution protocols (verify LLMNR, NBT-NS, and mDNS are disabled via GPO).
[ ] NET-INT-06: Verify segmentation between User Workstations, Server DMZ, Database Clusters, and Management VLANs.
[ ] NET-INT-07: Test egress filtering (verify restricted outbound ports from servers; block outbound SMB [445] and LDAP).

========================================================================================================================
CHECKLIST SECTION 3: ACTIVE DIRECTORY DOMAIN SERVICES (AD DS) AUDIT
========================================================================================================================
[ ] AD-DOM-01: Enumerate Active Directory domain architecture, functional level, forest trusts, and domain controllers.
[ ] AD-DOM-02: Execute BloodHound / SharpHound data collection to analyze non-obvious ACL privilege escalation paths.
[ ] AD-DOM-03: Audit Kerberos pre-authentication settings (identify accounts with `DONT_REQ_PREAUTH` for AS-REP Roasting).
[ ] AD-DOM-04: Audit Service Principal Names (SPNs) on user accounts (identify high-privilege targets for Kerberoasting).
[ ] AD-DOM-05: Audit Domain Controller replication permissions (identify non-admin accounts with `GetChanges` / `GetChangesAll`).
[ ] AD-DOM-06: Audit Unconstrained Delegation on computers and accounts (verify absence on perimeter servers).
[ ] AD-DOM-07: Audit Constrained Delegation and Protocol Transition (`S4U2Self`, `S4U2Proxy`) configurations.
[ ] AD-DOM-08: Audit Resource-Based Constrained Delegation (RBCD) permissions on computer objects.
[ ] AD-DOM-09: Audit SMB Signing configuration across all workstations and servers (enforce `RequireMessageSigned = true`).
[ ] AD-DOM-10: Audit LDAP signing and channel binding requirements on Domain Controllers (prevent cleartext LDAP / NTLM relay).
[ ] AD-DOM-11: Audit Active Directory Certificate Services (ADCS) for ESC1, ESC2, ESC3, ESC4, and ESC8 misconfigurations.
[ ] AD-DOM-12: Audit Local Administrator Password Solution (LAPS) deployment coverage across all domain-joined endpoints.
[ ] AD-DOM-13: Audit Group Policy Object (GPO) permissions (ensure non-administrative users cannot write to sysvol GPO scripts).
[ ] AD-DOM-14: Audit Privileged Access Workstation (PAW) architecture and Tier-0 / Tier-1 / Tier-2 administrative boundary hygiene.
```

---

## 4. REST, GraphQL & gRPC API Security Checklist (OWASP API Top 10 2023)

```
========================================================================================================================
CHECKLIST SECTION 1: REST API SECURITY CONTROLS
========================================================================================================================
[ ] API-REST-01 (API1: BOLA): Validate object-level access controls on every stateful endpoint (`/api/v1/orders/{id}`).
[ ] API-REST-02 (API2: Broken Auth): Verify JWT signing keys, enforce strong asymmetric algorithms (RS256/ES256), ban `none`.
[ ] API-REST-03 (API2: Broken Auth): Ensure JWT tokens have appropriate `exp` expiration, issuer (`iss`), and audience (`aud`).
[ ] API-REST-04 (API3: BOPLA): Audit input schemas for Mass Assignment (prohibit clients from binding `role`, `isAdmin`, `balance`).
[ ] API-REST-05 (API3: BOPLA): Audit response payloads for Excessive Data Exposure (ensure sensitive PII/keys are not returned).
[ ] API-REST-06 (API4: Unrestricted Resource): Validate presence of global and per-client rate limits (`429 Too Many Requests`).
[ ] API-REST-07 (API4: Unrestricted Resource): Enforce strict maximum payload sizes, request timeouts, and array bounds.
[ ] API-REST-08 (API5: BFLA): Test administrative API paths for Missing Function Level Authorization (`/api/admin/users`).
[ ] API-REST-09 (API6: Business Flows): Audit high-value business endpoints (checkout, coupon apply) against automated abuse.
[ ] API-REST-10 (API7: SSRF): Validate webhooks, URL-fetching parameters, and image download endpoints with strict allowlists.
[ ] API-REST-11 (API8: Misconfig): Verify disabling of CORS wildcard reflections, debug stacks, and default API gateway routes.
[ ] API-REST-12 (API9: Improper Inventory): Enumerate deprecated API versions (`/v1/`, `/v2/`, `/beta/`) and unauthenticated test endpoints.
[ ] API-REST-13 (API10: Unsafe Consumption): Validate third-party API response sanitization before processing in backends.

========================================================================================================================
CHECKLIST SECTION 2: GRAPHQL & GRPC PROTOCOL-SPECIFIC CONTROLS
========================================================================================================================
[ ] API-GQL-01: Audit GraphQL Introspection (ensure schema introspection is disabled in production environments).
[ ] API-GQL-02: Test for Query Depth and Complexity Attacks (enforce maximum query depth and cost-analysis plugins).
[ ] API-GQL-03: Test for GraphQL Batching Attacks (verify limits on multi-query execution within single HTTP request).
[ ] API-GQL-04: Verify Field-Level Authorization within resolver functions (ensure child nodes inherit auth checks).
[ ] API-GRPC-01: Audit gRPC Server Reflection (ensure `grpc.reflection.v1alpha.ServerReflection` is disabled in production).
[ ] API-GRPC-02: Verify Mutual TLS (mTLS) enforcement between internal microservices over HTTP/2 transport.
[ ] API-GRPC-03: Test gRPC Metadata authentication interceptors for bearer token extraction and validation.
[ ] API-GRPC-04: Enforce Protobuf field validation constraints (`protoc-gen-validate`) on string lengths and regexes.
```

---

## 5. Android & Mobile Security Checklist (OWASP MASVS Aligned)

```
========================================================================================================================
CHECKLIST SECTION 1: ARCHITECTURE, STORAGE & CRYPTOGRAPHY (MASVS-STORAGE & MASVS-CRYPTO)
========================================================================================================================
[ ] MOB-STR-01: Audit `SharedPreferences` for plaintext tokens, credentials, or personal sensitive information.
[ ] MOB-STR-02: Audit SQLite databases and Realm files (verify SQLCipher encryption and absence of sensitive caching).
[ ] MOB-STR-03: Audit external storage access (ensure app does not write sensitive files to `/sdcard/` or shared storage).
[ ] MOB-STR-04: Verify keyboard cache disablement (`inputType="textNoSuggestions|textPassword"`) on sensitive fields.
[ ] MOB-STR-05: Audit Android Logcat output (ensure no credentials, API keys, or session tokens are emitted via `Log.*`).
[ ] MOB-STR-06: Audit application backup settings (ensure `android:allowBackup="false"` in `AndroidManifest.xml`).
[ ] MOB-CRY-01: Verify cryptographic keys are generated and stored inside the hardware-backed Android KeyStore.
[ ] MOB-CRY-02: Audit cipher modes (enforce AES-GCM or ChaCha20-Poly1305; eliminate AES-ECB and DES/3DES).
[ ] MOB-CRY-03: Audit random number generators (verify `java.security.SecureRandom` instead of `java.util.Random`).
[ ] MOB-CRY-04: Scan compiled assets and decompiled Smali for hardcoded API secrets, symmetric keys, or private certs.

========================================================================================================================
CHECKLIST SECTION 2: AUTHENTICATION, NETWORK & IPC PLATFORM (MASVS-AUTH, NETWORK & PLATFORM)
========================================================================================================================
[ ] MOB-NET-01: Audit `res/xml/network_security_config.xml` (verify cleartext traffic is explicitly disabled: `cleartextTrafficPermitted="false"`).
[ ] MOB-NET-02: Test SSL/TLS Certificate Pinning implementation and verify resilience against custom CA injection.
[ ] MOB-NET-03: Verify TLS protocol configuration (enforce TLS 1.2+ for all network calls).
[ ] MOB-AUT-01: Audit biometric authentication implementation (ensure `BiometricPrompt` utilizes CryptoObject bound to KeyStore).
[ ] MOB-AUT-02: Verify local authentication fallbacks and session termination upon app backgrounding/timeout.
[ ] MOB-PLT-01: Audit exported Android components (`android:exported="true"`) in `AndroidManifest.xml`.
[ ] MOB-PLT-02: Test exported Activities for unauthenticated access or sensitive intent parameter injection.
[ ] MOB-PLT-03: Test exported Broadcast Receivers for spoofed broadcast execution.
[ ] MOB-PLT-04: Test exported Content Providers for SQL Injection and unauthorized file disclosure via `openFile()`.
[ ] MOB-PLT-05: Audit Android Deep Links / App Links for parameter tampering and arbitrary web redirects.

========================================================================================================================
CHECKLIST SECTION 3: CODE RESILIENCY & RUNTIME INTEGRITY (MASVS-RESILIENCE)
========================================================================================================================
[ ] MOB-RES-01: Verify ProGuard / R8 code obfuscation and symbol stripping on release builds.
[ ] MOB-RES-02: Verify `android:debuggable="false"` in production AndroidManifest.xml.
[ ] MOB-RES-03: Audit root detection mechanisms (SafetyNet / Play Integrity API, `su` binary checks, build tags).
[ ] MOB-RES-04: Audit runtime hooking defenses (Frida detection, ptrace anti-debugging, memory scanner hooks).
[ ] MOB-RES-05: Verify application signature verification and APK tampering detection checks.
```

---

## 6. Operational Evidence Collection & Triage Matrix

For every finding identified during checklist execution, the auditor must collect the standard evidentiary bundle prior to defect submission:

```
+----------------------------------------------------------------------------------------------------+
| Finding Severity | Mandatory Evidentiary Artifacts Required for Report Acceptance                   |
+----------------------------------------------------------------------------------------------------+
| CRITICAL         | 1. Full raw HTTP/Protocol request and response logs with headers.               |
| (CVSS 9.0-10.0)  | 2. Non-destructive proof (e.g., mathematical execution `7*7=49`, read `/proc`). |
|                  | 3. Step-by-step reproduction command using `curl`, `nmap`, or standard CLI.     |
|                  | 4. Exact asset FQDN, listening port, and affected code parameter/file.           |
+----------------------------------------------------------------------------------------------------+
| HIGH             | 1. Full raw request and response demonstrating unauthorized data leakage.       |
| (CVSS 7.0-8.9)   | 2. Proof of boundary crossing (e.g., User A accessing User B identifier).       |
|                  | 3. Description of root-cause flaw and proposed source code patch.               |
+----------------------------------------------------------------------------------------------------+
| MEDIUM           | 1. Tool output or protocol transcript demonstrating configuration defect.        |
| (CVSS 4.0-6.9)   | 2. Impact evaluation demonstrating realistic exploitation prerequisites.        |
|                  | 3. Framework-specific remediation settings.                                     |
+----------------------------------------------------------------------------------------------------+
| LOW / INFO       | 1. Banner, certificate, or header output demonstrating missing defense-in-depth. |
| (CVSS 0.1-3.9)   | 2. Industry benchmark citation (CIS Benchmark, RFC, OWASP ASVS).                |
+----------------------------------------------------------------------------------------------------+
```
