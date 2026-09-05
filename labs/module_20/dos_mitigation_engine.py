#!/usr/bin/env python3
"""
DoS Threat Engineering & Rate Limiting Engine
Standalone diagnostic tool for calculating UDP amplification multipliers,
simulating RFC 4987 TCP SYN Cookies, detecting ReDoS catastrophic backtracking,
and implementing Token Bucket rate limiting.
"""

import sys
import os
import time
import re
import hmac
import hashlib
import struct
from typing import Dict, List, Tuple, Optional

# Operational Redaction Helper
def redact_string(val: str, prefix_len: int = 4) -> str:
    """Redacts sensitive values to first 4 chars + ****REDACTED."""
    if len(val) <= prefix_len:
        return val[:prefix_len] + "****REDACTED"
    return val[:prefix_len] + "****REDACTED"

def calculate_udp_amplification(protocol: str, request_bytes: int) -> Dict[str, any]:
    """
    Calculates expected response size and amplification factor for known reflection protocols.
    Based on US-CERT and Cloudflare empirical threat telemetry.
    """
    amplification_database = {
        "memcached": {"multiplier": 50000, "port": 11211, "risk": "CRITICAL"},
        "ntp_monlist": {"multiplier": 556, "port": 123, "risk": "CRITICAL"},
        "dns_any_edns0": {"multiplier": 54, "port": 53, "risk": "HIGH"},
        "cldap": {"multiplier": 70, "port": 389, "risk": "HIGH"},
        "ssdp": {"multiplier": 30, "port": 1900, "risk": "MEDIUM"},
        "chargen": {"multiplier": 358, "port": 19, "risk": "HIGH"}
    }
    
    proto_key = protocol.lower().replace(" ", "_")
    data = amplification_database.get(proto_key, {"multiplier": 1, "port": 0, "risk": "LOW"})
    multiplier = data["multiplier"]
    reflected_bytes = request_bytes * multiplier
    
    return {
        "Protocol": protocol.upper(),
        "Port": data["port"],
        "Request_Bytes": request_bytes,
        "Amplified_Response_Bytes": reflected_bytes,
        "Amplification_Factor": f"{multiplier}x",
        "Risk_Classification": data["risk"]
    }

def generate_syn_cookie(src_ip: str, src_port: int, dst_ip: str, dst_port: int, mss_index: int, secret_key: bytes) -> int:
    """
    Simulates RFC 4987 TCP SYN Cookie generation.
    ISN = Truncated_HMAC_SHA1(secret, src_ip || dst_ip || src_port || dst_port || timestamp_window) + mss_index
    Returns a 32-bit Initial Sequence Number (ISN).
    """
    time_window = int(time.time() // 64) & 0x07 # 3-bit slow timestamp
    data = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{time_window}".encode('utf-8')
    digest = hmac.new(secret_key, data, hashlib.sha1).digest()
    
    # Extract 24-bit integer from digest
    truncated_hash = struct.unpack(">I", digest[:4])[0] & 0x00FFFFFF
    # Combine: [24 bits hash] [3 bits time] [3 bits mss_index] [2 bits padding]
    cookie = (truncated_hash << 8) | (time_window << 5) | ((mss_index & 0x07) << 2)
    return cookie & 0xFFFFFFFF

def verify_syn_cookie(ack_seq_num: int, src_ip: str, src_port: int, dst_ip: str, dst_port: int, secret_key: bytes) -> bool:
    """
    Validates the client's final ACK sequence number (which must equal cookie + 1).
    Validates without allocating any server state memory.
    """
    expected_cookie = (ack_seq_num - 1) & 0xFFFFFFFF
    # Extract stored time_window and mss_index from cookie
    time_window = (expected_cookie >> 5) & 0x07
    mss_index = (expected_cookie >> 2) & 0x07
    
    current_window = int(time.time() // 64) & 0x07
    # Allow current and immediately preceding time window (tolerance for latency)
    valid_windows = [current_window, (current_window - 1) & 0x07]
    if time_window not in valid_windows:
        return False
        
    data = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{time_window}".encode('utf-8')
    digest = hmac.new(secret_key, data, hashlib.sha1).digest()
    truncated_hash = struct.unpack(">I", digest[:4])[0] & 0x00FFFFFF
    
    recomputed_cookie = ((truncated_hash << 8) | (time_window << 5) | ((mss_index & 0x07) << 2)) & 0xFFFFFFFF
    return expected_cookie == recomputed_cookie

def audit_redos_backtracking(pattern_str: str, max_length: int = 22) -> Dict[str, any]:
    """
    Audits a regular expression for catastrophic backtracking (CWE-1333).
    Tests increasing input lengths against non-matching terminal characters.
    """
    compiled = re.compile(pattern_str)
    times = []
    
    for length in range(12, max_length + 1, 2):
        payload = ("a" * length) + "!"
        t0 = time.time()
        compiled.match(payload)
        elapsed = time.time() - t0
        times.append((length, elapsed))
        
    is_vulnerable = False
    if len(times) >= 3 and times[-1][1] > 0.02:
        # Check if execution time is expanding exponentially
        ratio = times[-1][1] / max(times[-2][1], 0.0001)
        if ratio > 1.8:
            is_vulnerable = True
            
    return {
        "Pattern": pattern_str,
        "Timing_Progression": times,
        "Is_ReDoS_Vulnerable": is_vulnerable,
        "Risk_Level": "CRITICAL" if is_vulnerable else "LOW"
    }

class TokenBucketRateLimiter:
    """
    Simulates a Token Bucket rate-limiting algorithm.
    Capacity: maximum token burst buffer.
    Refill_Rate: tokens added per second.
    """
    def __init__(self, capacity: int, refill_rate_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_rate = refill_rate_per_sec
        self.last_update = time.time()

    def request(self, tokens_requested: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
        self.last_update = now

        if self.tokens >= tokens_requested:
            self.tokens -= tokens_requested
            return True
        return False

def run_self_tests():
    print("[*] Running DoS Threat Engineering & Rate Limiting Engine Self-Tests...")

    # Test 1: UDP Amplification Calculation
    memcached_res = calculate_udp_amplification("memcached", 15)
    assert memcached_res["Amplified_Response_Bytes"] == 15 * 50000
    assert memcached_res["Risk_Classification"] == "CRITICAL"
    print(f"[+] Test 1 Passed: Memcached amplification evaluated at {memcached_res['Amplification_Factor']}.")

    # Test 2: TCP SYN Cookie Generation & Verification
    secret = b"K3rn3lS3cr3tKey2026!"
    src_ip, src_port = "192.0.2.10", 54321
    dst_ip, dst_port = "198.51.100.5", 443
    mss_idx = 2
    
    cookie = generate_syn_cookie(src_ip, src_port, dst_ip, dst_port, mss_idx, secret)
    assert isinstance(cookie, int)
    assert 0 <= cookie <= 0xFFFFFFFF
    
    # Verify valid client response (cookie + 1)
    client_ack = (cookie + 1) & 0xFFFFFFFF
    assert verify_syn_cookie(client_ack, src_ip, src_port, dst_ip, dst_port, secret) is True
    
    # Verify tampered packet response
    assert verify_syn_cookie(client_ack + 42, src_ip, src_port, dst_ip, dst_port, secret) is False
    print("[+] Test 2 Passed: RFC 4987 TCP SYN Cookie generation & stateless verification verified.")

    # Test 3: ReDoS Catastrophic Backtracking Detection (CWE-1333)
    evil_pattern = r"^(a+)+$"
    redos_res = audit_redos_backtracking(evil_pattern, max_length=20)
    assert redos_res["Is_ReDoS_Vulnerable"] is True
    assert redos_res["Risk_Level"] == "CRITICAL"
    print(f"[+] Test 3 Passed: ReDoS engine detected catastrophic backtracking in '{evil_pattern}'.")

    # Test 4: Token Bucket Rate Limiter
    # Capacity 3 tokens, refill 0.1 tokens/sec (essentially static for this test)
    limiter = TokenBucketRateLimiter(capacity=3, refill_rate_per_sec=0.1)
    # Burst 3 requests: all should be allowed
    assert limiter.request(1.0) is True
    assert limiter.request(1.0) is True
    assert limiter.request(1.0) is True
    # 4th request: bucket empty, must be rejected (HTTP 429)
    assert limiter.request(1.0) is False
    print("[+] Test 4 Passed: Token Bucket rate limiter permitted burst of 3 and blocked 4th request.")

    print("[*] All DoS Threat Engineering & Rate Limiting tests completed with 100% success.")

if __name__ == "__main__":
    run_self_tests()
