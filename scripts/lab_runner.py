#!/usr/bin/env python3
"""
Ethical Hacking & VAPT Master Notes — Central Lab Suite Manager & Test Runner
Architecture: Zero External Dependencies (Standard Library Python 3.8+)
Author: Tejas's Ethical Hacking & VAPT Curriculum

Provides a unified interface for:
- Listing all 34 module diagnostic labs
- Running individual module lab suites by number
- Executing full repository regression sweeps
- Checking host environment and prerequisite tools
- Interactive terminal selection menu
"""

import sys
import os
import glob
import subprocess
import time
import shutil
from typing import Dict, List, Tuple, Optional

# ANSI Color codes for clean terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        cls.HEADER = ""
        cls.BLUE = ""
        cls.CYAN = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.RED = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RESET = ""

# Disable colors if stdout is redirected to non-tty
if not sys.stdout.isatty():
    Colors.disable()

# Base repo path resolution
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Module Registry: Maps module number (int) -> (title, script_rel_path, description)
MODULE_REGISTRY: Dict[int, Tuple[str, str, str]] = {
    1: (
        "Hardware & OS Microarchitecture Security",
        "labs/module_01/hardware_os_security_auditor.py",
        "Audits CPU microarchitecture flags (NX/DEP, SMEP, SMAP, KPTI) and Linux ASLR memory randomization."
    ),
    2: (
        "Secure SDLC & Threat Modeling",
        "labs/module_02/secure_sdlc_threat_modeler.py",
        "STRIDE threat modeling, DREAD scoring matrix, and SAST source-to-sink taint analysis."
    ),
    3: (
        "Scoping & RoE Boundary Guard",
        "labs/module_03/scope_enforcement_guard.py",
        "Scoping guardrails, CIDR boundary validation, and out-of-scope target containment."
    ),
    4: (
        "Virtual Lab Topology & Container Security",
        "labs/module_04/virtual_lab_topology_checker.py",
        "Audits multi-NIC pivot topologies, RFC 1918 compliance, and Docker container privilege breakout risks."
    ),
    5: (
        "Linux Security & Privilege Escalation Audit",
        "labs/module_05/linux_security_audit.sh",
        "Linux kernel inspection, SUID/SGID auditing, world-writable file checks, and permission flaws."
    ),
    6: (
        "OSINT & Passive Footprinting Engine",
        "labs/module_06/osint_footprint_engine.py",
        "Passive OSINT footprinting, Certificate Transparency mining, DNS SPF/DMARC records, and WHOIS parsing."
    ),
    7: (
        "Service Enumeration & Protocol Auditing",
        "labs/module_07/service_enumeration_auditor.py",
        "Service enumeration, banner grabbing, SMB dialect negotiation, and RPC port mapping parser."
    ),
    8: (
        "Raw Network Packet Dissector",
        "labs/module_08/network_packet_dissector.py",
        "Raw socket IPv4, TCP (3-way handshake flags) and UDP header dissector with checksum verification."
    ),
    9: (
        "Anonymity, Tor & Privacy Leak Auditor",
        "labs/module_09/anonymity_leak_auditor.py",
        "Tor circuit integrity, DNS leak detection, WebRTC STUN candidate parsing, and IPv6 leakage auditing."
    ),
    10: (
        "Password Security & Cryptographic KDFs",
        "labs/module_10/credential_security_auditor.py",
        "KDF work factor benchmarking (PBKDF2/Argon2/bcrypt), Shannon entropy, and password policy auditing."
    ),
    11: (
        "Layer 2 Security & Dynamic ARP Inspection",
        "labs/module_11/layer2_security_auditor.py",
        "ARP spoofing detection, Dynamic ARP Inspection (DAI) state engine, and MAC table exhaustion defense."
    ),
    12: (
        "Human Risk & Social Engineering Evaluator",
        "labs/module_12/human_risk_evaluator.py",
        "Psychometric pretext lure analyzer, Cialdini persuasion heuristic scoring, and phishing metrics."
    ),
    13: (
        "Wireless 802.11 Security Auditor",
        "labs/module_13/wireless_security_auditor.py",
        "802.11 frame parser, WPA2 4-way handshake PMK/PTK synthesizer, PMKID extractor, and 802.11w auditor."
    ),
    14: (
        "Host Defense & Registry ASEP Auditor",
        "labs/module_14/host_defense_auditor.py",
        "CWE-428 unquoted service paths, Windows Run/RunOnce ASEP registry keys, and Sysmon event parser."
    ),
    15: (
        "Phishing Architecture & Email Authentication",
        "labs/module_15/phishing_analysis_engine.py",
        "RFC 5321/5322 header alignment, SPF DNS lookup tree, DKIM verification, and AiTM reverse proxy detector."
    ),
    16: (
        "Malware Analysis & Section Entropy Engine",
        "labs/module_16/malware_analysis_engine.py",
        "Portable Executable (PE) / ELF section entropy, import hash (imphash) calculator, and YARA rule engine."
    ),
    17: (
        "Android Storage & Manifest Security Auditor",
        "labs/module_17/android_storage_and_manifest_auditor.py",
        "AndroidManifest.xml parser (exported components, debuggable flags) and SQLite storage auditor."
    ),
    18: (
        "SIEM Detection Rules & RBA Engine",
        "labs/module_18/siem_detection_engine.py",
        "Sigma detection rule parser, Splunk/Elasticsearch query translator, and risk-based alerting (RBA)."
    ),
    19: (
        "Email Security Protocols & Header Forensics",
        "labs/module_19/audit_email_headers.py",
        "Chronological 'Received:' hop parser, spoofed boundary detection, and DMARC forensic analyzer."
    ),
    20: (
        "DoS Mitigation & Rate Limiting Engine",
        "labs/module_20/dos_mitigation_engine.py",
        "UDP amplification factor, RFC 4987 SYN cookies, ReDoS polynomial time check, and Token Bucket limiter."
    ),
    21: (
        "Web Security Foundations & CORS Auditor",
        "labs/module_21/cors_header_auditor.py",
        "Same-Origin Policy (SOP), CORS misconfigurations (null origin, credential reflection), and security headers."
    ),
    22: (
        "IoT Embedded Security & Firmware Auditor",
        "labs/module_22/audit_iot_firmware.py",
        "Binwalk header signature detection, SquashFS entropy analysis, and hardcoded credential scanner."
    ),
    23: (
        "Steganography & Digital Forensics Lab",
        "labs/module_23/stego_forensics_lab.py",
        "24-bit BMP & PNG Least Significant Bit (LSB) steganography injector, extractor, and Chi-Square detector."
    ),
    24: (
        "Applied Cryptography & PKI Chain Verifier",
        "labs/module_24/pki_crypto_audit.py",
        "Cryptographic cipher suite auditor, RSA/ECC key generator, X.509 certificate chain verifier, and CRL check."
    ),
    25: (
        "Cyber Laws & Evidence Custody Verifier",
        "labs/module_25/evidence_custody_verifier.py",
        "Cryptographic chain-of-custody ledger with SHA-256 block-hashing and tamper verification."
    ),
    26: (
        "Digital Evidence Chain-of-Custody Sealer",
        "labs/module_26/evidence_chain_of_custody_sealer.py",
        "Dual-hash (SHA-256 + SHA-512) digital evidence sealing tool conforming to ISO/IEC 27037 standards."
    ),
    27: (
        "Network Containment & Boundary Auditor",
        "labs/module_27/network_containment_auditor.py",
        "Multi-subnet boundary validation, routing table inspector, and unauthorized egress containment auditor."
    ),
    28: (
        "Web Surface Mapping & JS Endpoint Extractor",
        "labs/module_28/web_surface_mapper.py",
        "HTML/DOM parser, technology stack fingerprinting engine, and JavaScript API endpoint discovery parser."
    ),
    29: (
        "Web Fuzzing & Upstream Proxy Engine",
        "labs/module_29/fuzz_and_proxy_engine.py",
        "Multi-threaded HTTP fuzzing engine, wordlist mutation, path fuzzing, and Burp upstream proxy adapter."
    ),
    30: (
        "OWASP Top 10 Vulnerability & Defense Lab",
        "labs/module_30/owasp_top10_lab.py",
        "OWASP Top 10 vulnerability lab: SQLi, XSS, IDOR, SSRF, SSTI, Mass Assignment, and Secure Patches."
    ),
    31: (
        "VAPT Reporting & CVSS v3.1/v4.0 Scoring",
        "labs/module_31/vapt_report_and_cvss_engine.py",
        "CVSS v3.1 and v4.0 vector scoring calculator and structured executive/technical Markdown report generator."
    ),
    32: (
        "Service Auditing & Network Pivot Engine",
        "labs/module_32/service_audit_and_pivot_engine.py",
        "Network pivot simulation, SMB signing auditor, anonymous FTP scanner, and relay boundary verification."
    ),
    33: (
        "API Testing & Microservice Security Engine",
        "labs/module_33/api_security_testing_engine.py",
        "JWT algorithm confusion ('none' alg), API Mass Assignment, and GraphQL nested query depth auditor."
    ),
    34: (
        "Android App VAPT & Frida Hook Synthesizer",
        "labs/module_34/apk_reversing_and_frida_engine.py",
        "Smali bytecode inverter, hardcoded API secret scanner, and dynamic Frida JavaScript hook synthesizer."
    )
}


def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("================================================================================")
    print("      ETHICAL HACKING & VAPT MASTER LAB SUITE — EXECUTION MANAGER")
    print("================================================================================")
    print(f"{Colors.RESET}{Colors.DIM}Standards: NIST SP 800-115 | OWASP Top 10/ASVS | PTES | MITRE ATT&CK{Colors.RESET}\n")


def list_modules():
    print_banner()
    print(f"{Colors.BOLD}{'Mod #':<6} {'Title':<42} {'Script Path':<40}{Colors.RESET}")
    print("-" * 90)
    for mod_num in sorted(MODULE_REGISTRY.keys()):
        title, path, _ = MODULE_REGISTRY[mod_num]
        print(f"{Colors.YELLOW}{mod_num:02d}{Colors.RESET}     {Colors.BOLD}{title[:40]:<42}{Colors.RESET} {Colors.DIM}{path}{Colors.RESET}")
    print("\n" + f"{Colors.GREEN}Total Registered Labs: {len(MODULE_REGISTRY)}{Colors.RESET}")
    print(f"Run a specific lab:  {Colors.BOLD}make run MODULE=<number>{Colors.RESET} or {Colors.BOLD}python3 scripts/lab_runner.py --run <number>{Colors.RESET}\n")


def run_single_module(mod_num: int) -> int:
    if mod_num not in MODULE_REGISTRY:
        print(f"{Colors.RED}[!] Error: Module {mod_num} does not exist. Available modules: 01 to 34.{Colors.RESET}")
        return 1

    title, rel_path, desc = MODULE_REGISTRY[mod_num]
    abs_path = os.path.join(REPO_ROOT, rel_path)

    if not os.path.isfile(abs_path):
        print(f"{Colors.RED}[!] Error: Script not found at {abs_path}{Colors.RESET}")
        return 1

    print_banner()
    print(f"{Colors.BOLD}Executing Lab for Module {mod_num:02d}: {title}{Colors.RESET}")
    print(f"{Colors.DIM}Description: {desc}{Colors.RESET}")
    print(f"{Colors.DIM}Script:      {rel_path}{Colors.RESET}")
    print("-" * 80 + "\n")

    cmd = ["python3", abs_path] if abs_path.endswith(".py") else ["bash", abs_path]
    start_time = time.time()
    try:
        proc = subprocess.run(cmd, cwd=REPO_ROOT)
        elapsed = time.time() - start_time
        print("\n" + "-" * 80)
        if proc.returncode == 0:
            print(f"{Colors.GREEN}[+] Module {mod_num:02d} completed successfully (Exit Code 0) in {elapsed:.2f}s.{Colors.RESET}\n")
        else:
            print(f"{Colors.RED}[!] Module {mod_num:02d} exited with error code {proc.returncode} in {elapsed:.2f}s.{Colors.RESET}\n")
        return proc.returncode
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Execution interrupted by user.{Colors.RESET}")
        return 130


def test_all_modules() -> int:
    print_banner()
    print(f"{Colors.BOLD}Initiating Full Regression Suite Across All {len(MODULE_REGISTRY)} Lab Modules...{Colors.RESET}\n")
    print(f"{'Mod #':<6} {'Module Title':<42} {'Status':<12} {'Elapsed':<10}")
    print("-" * 75)

    passed_count = 0
    failed_modules = []
    total_start = time.time()

    for mod_num in sorted(MODULE_REGISTRY.keys()):
        title, rel_path, _ = MODULE_REGISTRY[mod_num]
        abs_path = os.path.join(REPO_ROOT, rel_path)

        cmd = ["python3", abs_path] if abs_path.endswith(".py") else ["bash", abs_path]
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        t1 = time.time()
        elapsed = t1 - t0

        if res.returncode == 0:
            status_str = f"{Colors.GREEN}PASS{Colors.RESET}"
            passed_count += 1
            print(f"{mod_num:02d}     {title[:40]:<42} {status_str:<21} {elapsed:.2f}s")
        else:
            status_str = f"{Colors.RED}FAIL (Exit {res.returncode}){Colors.RESET}"
            failed_modules.append((mod_num, title, res.stderr.strip()[:100]))
            print(f"{mod_num:02d}     {title[:40]:<42} {status_str:<21} {elapsed:.2f}s")

    total_elapsed = time.time() - total_start
    print("-" * 75)
    print(f"\n{Colors.BOLD}Regression Test Results:{Colors.RESET}")
    print(f"Total Modules Tested : {len(MODULE_REGISTRY)}")
    print(f"Passed               : {Colors.GREEN}{passed_count}{Colors.RESET}")
    print(f"Failed               : {Colors.RED if failed_modules else Colors.GREEN}{len(failed_modules)}{Colors.RESET}")
    print(f"Total Execution Time : {total_elapsed:.2f}s")

    if failed_modules:
        print(f"\n{Colors.RED}[!] Failures Encountered:{Colors.RESET}")
        for num, t, err in failed_modules:
            print(f"  - Module {num:02d} ({t}): {err}")
        return 1
    else:
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] 100% REGRESSION TESTS PASSED! All labs are functioning deterministically.{Colors.RESET}\n")
        return 0


def check_environment():
    print_banner()
    print(f"{Colors.BOLD}Auditing Local Host Environment Prerequisites:{Colors.RESET}\n")

    tools = [
        ("Python 3", ["python3", "--version"], True),
        ("POSIX Bash", ["bash", "--version"], True),
        ("Git", ["git", "--version"], True),
        ("Make", ["make", "--version"], False),
        ("Docker", ["docker", "--version"], False),
        ("Docker Compose", ["docker", "compose", "version"], False),
        ("OpenSSL", ["openssl", "version"], False),
        ("Nmap", ["nmap", "--version"], False)
    ]

    for tool_name, check_cmd, is_mandatory in tools:
        try:
            res = subprocess.run(check_cmd, capture_output=True, text=True)
            if res.returncode == 0:
                first_line = res.stdout.strip().splitlines()[0] if res.stdout else "Available"
                print(f"  {Colors.GREEN}[✓] {tool_name:<16}{Colors.RESET} Found: {Colors.DIM}{first_line[:50]}{Colors.RESET}")
            else:
                tag = f"{Colors.RED}[MANDATORY MISSING]" if is_mandatory else f"{Colors.YELLOW}[OPTIONAL MISSING]"
                print(f"  {tag} {tool_name:<16}{Colors.RESET}")
        except FileNotFoundError:
            tag = f"{Colors.RED}[MANDATORY MISSING]" if is_mandatory else f"{Colors.YELLOW}[OPTIONAL MISSING]"
            print(f"  {tag} {tool_name:<16}{Colors.RESET}")

    print("\n" + f"{Colors.CYAN}[*] Core Diagnostic Engine Requirements:{Colors.RESET}")
    print(f"    - All 34 Python/Bash labs run natively using standard library modules (Zero pip requirements).")
    print(f"    - Optional tools (Docker, Nmap, OpenSSL) enable live enterprise container enclaves.\n")


def interactive_menu():
    while True:
        print_banner()
        print(f"{Colors.BOLD}Main Menu Options:{Colors.RESET}")
        print("  1. List all 34 Lab Modules")
        print("  2. Run Full Regression Test Suite (34/34)")
        print("  3. Run an Individual Lab by Module Number")
        print("  4. Verify System Environment & Tools")
        print("  5. Exit")
        choice = input(f"\n{Colors.BOLD}Select an option (1-5): {Colors.RESET}").strip()

        if choice == "1":
            list_modules()
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
        elif choice == "2":
            test_all_modules()
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
        elif choice == "3":
            mod_input = input(f"{Colors.BOLD}Enter Module Number (1-34): {Colors.RESET}").strip()
            if mod_input.isdigit():
                run_single_module(int(mod_input))
            else:
                print(f"{Colors.RED}[!] Invalid number entered.{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
        elif choice == "4":
            check_environment()
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
        elif choice in ("5", "q", "exit"):
            print(f"{Colors.GREEN}Exiting lab manager. Happy ethical hacking!{Colors.RESET}\n")
            break
        else:
            print(f"{Colors.RED}[!] Invalid selection.{Colors.RESET}")
            time.sleep(1)


def main():
    if len(sys.argv) == 1 or sys.argv[1] in ("-h", "--help", "help"):
        print_banner()
        print(f"{Colors.BOLD}Usage:{Colors.RESET}")
        print("  python3 scripts/lab_runner.py --list                 List all 34 modules")
        print("  python3 scripts/lab_runner.py --test-all             Run full test suite (34/34)")
        print("  python3 scripts/lab_runner.py --run <mod_num>        Run a specific module lab")
        print("  python3 scripts/lab_runner.py --check-env            Audit host tools and prerequisites")
        print("  python3 scripts/lab_runner.py --interactive          Launch interactive terminal menu\n")
        print(f"{Colors.BOLD}Makefile Equivalents:{Colors.RESET}")
        print("  make list          |  make test")
        print("  make run MODULE=30 |  make setup")
        print("  make interactive   |  make help\n")
        sys.exit(0)

    arg = sys.argv[1]
    if arg in ("--list", "-l", "list"):
        list_modules()
    elif arg in ("--test-all", "-t", "test"):
        code = test_all_modules()
        sys.exit(code)
    elif arg in ("--check-env", "-c", "check"):
        check_environment()
    elif arg in ("--interactive", "-i", "interactive"):
        interactive_menu()
    elif arg in ("--run", "-r", "run"):
        if len(sys.argv) < 3:
            print(f"{Colors.RED}[!] Error: Please specify a module number. Example: python3 scripts/lab_runner.py --run 30{Colors.RESET}")
            sys.exit(1)
        try:
            mod_num = int(sys.argv[2])
            code = run_single_module(mod_num)
            sys.exit(code)
        except ValueError:
            print(f"{Colors.RED}[!] Error: Invalid module number '{sys.argv[2]}'. Must be an integer 1-34.{Colors.RESET}")
            sys.exit(1)
    else:
        print(f"{Colors.RED}[!] Unknown argument: {arg}. Run with --help for usage.{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
