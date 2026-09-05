#!/usr/bin/env python3
"""
SIEM Detection & Risk-Based Alerting (RBA) Engine
Standalone diagnostic tool for evaluating Sigma-style detection rules,
compiling rules to Splunk SPL / Elastic Lucene dialects, applying sliding-window
thresholds, and calculating dynamic entity risk scores.
"""

import sys
import os
import time
from typing import Dict, List, Any, Tuple, Optional

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive values to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def match_sigma_rule(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """
    Evaluates whether a normalized security event matches Sigma-style selection criteria.
    Supports exact matches, substrings, and multi-value lists (OR logic).
    """
    detection = rule.get("detection", {})
    selection = detection.get("selection", {})

    for field, expected in selection.items():
        event_val = str(event.get(field, "")).lower()
        if isinstance(expected, list):
            # If any value in the list matches, this field criterion is satisfied
            if not any(exp.lower() in event_val for exp in expected):
                return False
        else:
            if expected.lower() not in event_val:
                return False

    return True

def compile_sigma_to_splunk(rule: Dict[str, Any]) -> str:
    """Translates a simple Sigma rule into Splunk Search Processing Language (SPL)."""
    logsource = rule.get("logsource", {})
    product = logsource.get("product", "*")
    category = logsource.get("category", "*")
    
    query_parts = [f'index={product}', f'sourcetype="*{category}*"']
    selection = rule.get("detection", {}).get("selection", {})
    
    for field, val in selection.items():
        if isinstance(val, list):
            or_group = " OR ".join([f'{field}="*{v}*"' for v in val])
            query_parts.append(f"({or_group})")
        else:
            query_parts.append(f'{field}="*{val}*"')
            
    return " ".join(query_parts)

def compile_sigma_to_elastic(rule: Dict[str, Any]) -> str:
    """Translates a simple Sigma rule into Elasticsearch Lucene Query syntax."""
    query_parts = []
    selection = rule.get("detection", {}).get("selection", {})
    
    for field, val in selection.items():
        if isinstance(val, list):
            or_group = " OR ".join([f'{field}: "*{v}*"' for v in val])
            query_parts.append(f"({or_group})")
        else:
            query_parts.append(f'{field}: "*{val}*"')
            
    return " AND ".join(query_parts)

class RiskBasedAlertingEngine:
    """
    Accumulates entity risk scores across multiple correlated security events.
    Fires an operational high-priority alert only when risk score >= threshold.
    """
    def __init__(self, critical_threshold: int = 100):
        self.threshold = critical_threshold
        self.entity_scores: Dict[str, int] = {}       # entity -> total points
        self.entity_events: Dict[str, List[Dict[str, Any]]] = {} # entity -> matched events

    def process_event(self, event: Dict[str, Any], rule_catalog: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        entity = event.get("User") or event.get("Host") or event.get("Source_IP") or "unknown_entity"
        
        for rule in rule_catalog:
            if match_sigma_rule(event, rule):
                points = rule.get("risk_points", 25)
                self.entity_scores[entity] = self.entity_scores.get(entity, 0) + points
                
                if entity not in self.entity_events:
                    self.entity_events[entity] = []
                self.entity_events[entity].append({
                    "rule_name": rule.get("title"),
                    "points": points,
                    "event": event
                })

                # Check if entity breached critical risk threshold
                if self.entity_scores[entity] >= self.threshold:
                    total = self.entity_scores[entity]
                    history = self.entity_events[entity]
                    # Reset after dispatching to prevent continuous firing
                    self.entity_scores[entity] = 0
                    self.entity_events[entity] = []
                    return {
                        "alert": "RBA_CRITICAL_RISK_THRESHOLD_EXCEEDED",
                        "entity": entity,
                        "accumulated_risk_score": total,
                        "correlated_event_count": len(history),
                        "triggered_rules": [h["rule_name"] for h in history],
                        "recommended_action": "Execute SOAR PB-CONTAINMENT: Isolate host and revoke active tokens."
                    }
        return None

def detect_sliding_window_burst(events: List[Dict[str, Any]], match_key: str, match_value: str, threshold: int, window_seconds: float) -> Optional[Dict[str, Any]]:
    """
    Evaluates events in a sliding time window to detect bursts (e.g., brute-force login sweeps).
    """
    matching_events = [
        e for e in events 
        if e.get(match_key, "").lower() == match_value.lower()
    ]
    
    if len(matching_events) >= threshold:
        timestamps = [e.get("timestamp", 0) for e in matching_events]
        time_span = max(timestamps) - min(timestamps)
        if time_span <= window_seconds:
            return {
                "alert": "SLIDING_WINDOW_BURST_DETECTED",
                "matched_value": match_value,
                "event_count": len(matching_events),
                "time_span_seconds": round(time_span, 2),
                "threshold": threshold
            }
    return None

def run_self_tests():
    print("[*] Running SIEM Detection & RBA Engine Self-Tests...")

    # Sample Sigma Rule Definitions
    rule_recon = {
        "title": "Suspicious Reconnaissance Command Execution",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine": ["whoami.exe", "net.exe user", "nltest.exe"]
            }
        },
        "risk_points": 30
    }

    rule_powershell_enc = {
        "title": "Encoded PowerShell Execution",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image": "powershell.exe",
                "CommandLine": "-enc"
            }
        },
        "risk_points": 50
    }

    rule_shadow_delete = {
        "title": "Volume Shadow Copy Deletion",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine": ["vssadmin", "delete shadows"]
            }
        },
        "risk_points": 50
    }

    rule_catalog = [rule_recon, rule_powershell_enc, rule_shadow_delete]

    # Test 1: Sigma Rule Matching
    event_enc_ps = {
        "User": "admin_test",
        "Host": "WKSTN-402",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -w hidden -enc JABhID0..."
    }
    assert match_sigma_rule(event_enc_ps, rule_powershell_enc) is True
    assert match_sigma_rule(event_enc_ps, rule_shadow_delete) is False
    print("[+] Test 1 Passed: Sigma rule matching engine accurately classified events.")

    # Test 2: Sigma to Splunk Compilation
    spl_query = compile_sigma_to_splunk(rule_powershell_enc)
    assert "index=windows" in spl_query
    assert 'CommandLine="*-enc*"' in spl_query
    print(f"[+] Test 2 Passed: Splunk SPL compiled: {spl_query}")

    # Test 3: Sigma to Elastic Compilation
    elastic_query = compile_sigma_to_elastic(rule_recon)
    assert 'CommandLine: "*whoami.exe*"' in elastic_query
    print(f"[+] Test 3 Passed: Elastic Lucene compiled: {elastic_query}")

    # Test 4: Risk-Based Alerting (RBA) Threshold Accumulation
    rba = RiskBasedAlertingEngine(critical_threshold=100)
    
    # Event 1: Recon (30 points) -> Total 30 (No alert)
    res1 = rba.process_event({"User": "alice_finance", "Host": "SRV-01", "CommandLine": "whoami.exe /priv"}, rule_catalog)
    assert res1 is None
    
    # Event 2: Encoded PowerShell (50 points) -> Total 80 (No alert)
    res2 = rba.process_event({"User": "alice_finance", "Host": "SRV-01", "Image": "powershell.exe", "CommandLine": "powershell.exe -enc AAAA"}, rule_catalog)
    assert res2 is None
    
    # Event 3: Shadow Copy Deletion (50 points) -> Total 130 (Threshold >= 100 reached!)
    res3 = rba.process_event({"User": "alice_finance", "Host": "SRV-01", "CommandLine": "vssadmin delete shadows /quiet"}, rule_catalog)
    assert res3 is not None
    assert res3["alert"] == "RBA_CRITICAL_RISK_THRESHOLD_EXCEEDED"
    assert res3["accumulated_risk_score"] == 130
    assert len(res3["triggered_rules"]) == 3
    print(f"[+] Test 4 Passed: RBA Engine accumulated {res3['accumulated_risk_score']} points and fired critical alert.")

    # Test 5: Sliding-Window Burst Detection (Failed Login Bursts)
    now = time.time()
    burst_events = [
        {"timestamp": now + 0.1, "EventID": "4625", "User": "target_admin"},
        {"timestamp": now + 0.2, "EventID": "4625", "User": "target_admin"},
        {"timestamp": now + 0.3, "EventID": "4625", "User": "target_admin"},
        {"timestamp": now + 0.4, "EventID": "4625", "User": "target_admin"},
        {"timestamp": now + 0.5, "EventID": "4625", "User": "target_admin"}
    ]
    burst_res = detect_sliding_window_burst(burst_events, "EventID", "4625", threshold=5, window_seconds=2.0)
    assert burst_res is not None
    assert burst_res["event_count"] == 5
    print(f"[+] Test 5 Passed: Sliding-window burst detector caught 5 events in {burst_res['time_span_seconds']}s.")

    print("[*] All SIEM Detection & RBA Engine tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
