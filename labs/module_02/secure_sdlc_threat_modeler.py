#!/usr/bin/env python3
"""
Module 02 Lab: Secure SDLC Threat Modeling & SAST Taint Analysis Engine
Author: Tejas's Ethical Hacking & VAPT Curriculum
Architecture: Standalone Python 3 (Zero external pip dependencies)

Description:
Provides an automated diagnostic engine for Secure SDLC workflows:
1. Architecture Threat Modeler: STRIDE category mapping with DREAD risk calculation.
2. Lightweight Static Taint Tracer: Identifies untrusted sources flowing into dangerous sinks
   without passing through recognized sanitizers.
"""

import sys
import re
import json
from typing import Dict, List, Any, Optional

# --- SECTION 1: STRIDE & DREAD THREAT MODELER ---

STRIDE_CATEGORIES = {
    "S": "Spoofing (Authentication Defect)",
    "T": "Tampering (Integrity Defect)",
    "R": "Repudiation (Audit/Logging Defect)",
    "I": "Information Disclosure (Confidentiality Defect)",
    "D": "Denial of Service (Availability Defect)",
    "E": "Elevation of Privilege (Authorization Defect)"
}

class STRIDEThreatEvaluator:
    """
    Evaluates system components against STRIDE categories and scores using DREAD.
    DREAD Score = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5
    """

    @staticmethod
    def calculate_dread(damage: int, repro: int, exploit: int, affected: int, discover: int) -> float:
        for val in (damage, repro, exploit, affected, discover):
            if not (1 <= val <= 10):
                raise ValueError("DREAD values must be integers between 1 and 10.")
        score = (damage + repro + exploit + affected + discover) / 5.0
        return round(score, 2)

    @classmethod
    def evaluate_component(cls, component_name: str, component_type: str, stride_code: str,
                           dread_tuple: tuple) -> Dict[str, Any]:
        stride_cat = STRIDE_CATEGORIES.get(stride_code.upper(), "Unknown Category")
        dread_score = cls.calculate_dread(*dread_tuple)
        
        severity = "LOW"
        if dread_score >= 8.0:
            severity = "CRITICAL"
        elif dread_score >= 6.0:
            severity = "HIGH"
        elif dread_score >= 4.0:
            severity = "MEDIUM"

        return {
            "component": component_name,
            "type": component_type,
            "stride_category": stride_cat,
            "dread_score": dread_score,
            "severity": severity,
            "dread_breakdown": {
                "damage": dread_tuple[0],
                "reproducibility": dread_tuple[1],
                "exploitability": dread_tuple[2],
                "affected_users": dread_tuple[3],
                "discoverability": dread_tuple[4]
            }
        }


# --- SECTION 2: SAST TAINT TRACER ENGINE ---

KNOWN_SOURCES = [
    r"request\.args\.get\(['\"](?P<var>\w+)['\"]\)",
    r"request\.form\.get\(['\"](?P<var>\w+)['\"]\)",
    r"req\.body\.(?P<var>\w+)",
    r"sys\.argv\[\d+\]",
    r"input\(.*?\)"
]

KNOWN_SANITIZERS = [
    r"html\.escape\(",
    r"shlex\.quote\(",
    r"parameterized_query",
    r"int\(",
    r"validator\.clean\(",
    r"sanitize_\w+\("
]

DANGEROUS_SINKS = [
    (r"cursor\.execute\((?P<arg>.*?)\)", "CWE-89: SQL Injection"),
    (r"os\.system\((?P<arg>.*?)\)", "CWE-78: OS Command Injection"),
    (r"subprocess\.Popen\((?P<arg>.*?)\)", "CWE-78: OS Command Injection"),
    (r"eval\((?P<arg>.*?)\)", "CWE-95: Improper Neutralization of Code Injection"),
    (r"render_template_string\((?P<arg>.*?)\)", "CWE-1336: Server-Side Template Injection")
]

class SASTSourceSinkAuditor:
    """
    Lightweight Static Application Security Testing (SAST) taint tracer.
    Tracks tainted variables from ingress sources to operational sinks.
    """

    @classmethod
    def analyze_snippet(cls, code_snippet: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code_snippet.splitlines()
        tainted_vars = set()
        sanitized_vars = set()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()

            # 1. Check for variable assignment from sources or existing tainted variables
            assign_match = re.match(r"(?P<var>\w+)\s*=\s*(?P<expr>.*)", stripped)
            if assign_match:
                var_name = assign_match.group("var")
                expr = assign_match.group("expr")

                # Direct source match
                is_direct_taint = any(re.search(src, expr) for src in KNOWN_SOURCES)
                
                # Propagated taint match (references an already tainted variable)
                propagated_taint = any(tvar in expr for tvar in tainted_vars)
                
                is_sanitized = any(re.search(san, expr) for san in KNOWN_SANITIZERS)

                if (is_direct_taint or propagated_taint) and not is_sanitized:
                    tainted_vars.add(var_name)
                elif is_sanitized:
                    sanitized_vars.add(var_name)
                    if var_name in tainted_vars:
                        tainted_vars.remove(var_name)

            # 3. Check for sink invocations
            for sink_pattern, cwe in DANGEROUS_SINKS:
                match = re.search(sink_pattern, stripped)
                if match:
                    sink_arg = match.group("arg")
                    # Check if any tainted variable is referenced in the sink argument
                    for tvar in tainted_vars:
                        if tvar in sink_arg and tvar not in sanitized_vars:
                            findings.append({
                                "line": idx,
                                "code": stripped,
                                "cwe": cwe,
                                "tainted_variable": tvar,
                                "remediation": "Validate input using parameterized queries or strict type validation."
                            })

        return findings


# --- SECTION 3: DETERMINISTIC SELF-TEST SUITE ---

def run_self_tests() -> bool:
    print("[*] Running Secure SDLC Threat Modeler & SAST Self-Tests...")

    # Test 1: STRIDE & DREAD Calculation
    comp_eval = STRIDEThreatEvaluator.evaluate_component(
        component_name="User Authentication Service",
        component_type="Web Service",
        stride_code="S",
        dread_tuple=(9, 8, 8, 9, 7)
    )
    assert comp_eval["dread_score"] == 8.2, f"Expected DREAD 8.2, got {comp_eval['dread_score']}"
    assert comp_eval["severity"] == "CRITICAL", f"Expected CRITICAL, got {comp_eval['severity']}"
    print(f"[+] Test 1 Passed: STRIDE/DREAD correctly evaluated ({comp_eval['stride_category']}, Score: {comp_eval['dread_score']})")

    # Test 2: SAST Taint Analysis - Vulnerable Code Snippet
    vulnerable_code = """
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""
    findings = SASTSourceSinkAuditor.analyze_snippet(vulnerable_code)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert "CWE-89" in findings[0]["cwe"], f"Expected CWE-89, got {findings[0]['cwe']}"
    assert findings[0]["tainted_variable"] == "query"
    print(f"[+] Test 2 Passed: Unsanitized taint path detected -> {findings[0]['cwe']} at line {findings[0]['line']}")

    # Test 3: SAST Taint Analysis - Sanitized Code Snippet
    sanitized_code = """
user_id = request.args.get('id')
clean_id = int(user_id)
cursor.execute("SELECT * FROM users WHERE id = %s", (clean_id,))
"""
    safe_findings = SASTSourceSinkAuditor.analyze_snippet(sanitized_code)
    assert len(safe_findings) == 0, f"Expected 0 findings for sanitized flow, got {len(safe_findings)}"
    print("[+] Test 3 Passed: Sanitized code flow correctly verified as safe (zero false positives).")

    print("[*] All Secure SDLC Threat Modeler tests completed with 100% success.")
    return True


if __name__ == "__main__":
    if len(sys.argv) == 1:
        success = run_self_tests()
        sys.exit(0 if success else 1)
    else:
        print("Usage: python3 secure_sdlc_threat_modeler.py (Runs self-tests by default)")
