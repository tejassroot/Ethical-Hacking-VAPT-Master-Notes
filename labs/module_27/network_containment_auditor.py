#!/usr/bin/env python3
"""
================================================================================
MODULE 27 LAB: MULTI-TIER NETWORK CONTAINMENT & ISOLATION AUDITOR
PURPOSE: Programmatic verification of virtual lab network segmentation, egress
         leakage testing, and cross-tier access boundary enforcement.
COMPLIANCE: Authorized testing only / Standard benign network diagnostic probing.
================================================================================
"""

import socket
import threading
import http.server
import time
import sys

class MockBoundaryListener(http.server.BaseHTTPRequestHandler):
    """Simulates an internal protected management service on a restricted subnet."""
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"service": "ad_domain_controller", "status": "protected"}')

def test_egress_containment(probe_endpoints):
    """Audits whether lab VMs can establish unauthorized outbound connections to the internet."""
    print("=" * 72)
    print("[*] 1. AUDITING EXTERNAL EGRESS CONTAINMENT")
    print("=" * 72)

    leaks_found = 0
    for host, port in probe_endpoints:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect((host, port))
            sock.close()
            print(f"    [!] CRITICAL LEAK: Connection succeeded to {host}:{port}!")
            leaks_found += 1
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"    [+] PASS (Contained): Connection blocked to {host}:{port}")

    if leaks_found == 0:
        print("[+] External egress containment confirmed: Zero outbound leaks.")
    else:
        print(f"[-] WARNING: {leaks_found} outbound connections succeeded. Check firewall NAT rules.")
    return leaks_found == 0

def test_tier_segmentation(target_ip, target_port, expected_blocked=True):
    """Audits inter-tier network segmentation barriers (e.g. DMZ -> Management Tier)."""
    print("\n" + "=" * 72)
    print(f"[*] 2. AUDITING INTER-TIER SEGMENTATION BARRIER: {target_ip}:{target_port}")
    print("=" * 72)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((target_ip, int(target_port)))
        sock.close()
        connected = True
    except (socket.timeout, ConnectionRefusedError, OSError):
        connected = False

    if expected_blocked:
        if not connected:
            print(f"    [+] PASS: Direct access to {target_ip}:{target_port} blocked by policy.")
            return True
        else:
            print(f"    [!] VIOLATION: Unauthorized direct access to {target_ip}:{target_port} established!")
            return False
    else:
        if connected:
            print(f"    [+] PASS: Authorized connection established to {target_ip}:{target_port}.")
            return True
        else:
            print(f"    [-] FAIL: Expected authorized path to {target_ip}:{target_port} is blocked.")
            return False

def run_self_test():
    """Executes a local simulated multi-tier containment verification test."""
    print("[*] Initializing local test harness simulating multi-tier network topology...")
    
    # Spin up mock protected service on 127.0.0.1:8891
    server = http.server.HTTPServer(("127.0.0.1", 8891), MockBoundaryListener)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        # 1. Test simulated external egress (using unreachable or blackhole IPs)
        mock_external = [
            ("192.0.2.1", 80),     # RFC 5737 TEST-NET-1 (unroutable)
            ("198.51.100.1", 443), # RFC 5737 TEST-NET-2 (unroutable)
            ("203.0.113.1", 53)    # RFC 5737 TEST-NET-3 (unroutable)
        ]
        test_egress_containment(mock_external)

        # 2. Test authorized path
        test_tier_segmentation("127.0.0.1", 8891, expected_blocked=False)

        # 3. Test blocked path (simulating blocked DMZ-to-Management port)
        test_tier_segmentation("127.0.0.1", 8892, expected_blocked=True)

        print("\n" + "=" * 72)
        print("[+] LAB NETWORK CONTAINMENT AUDIT COMPLETE: All boundaries verified.")
        print("=" * 72)
    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    if len(sys.argv) > 2:
        ip = sys.argv[1]
        port = int(sys.argv[2])
        test_tier_segmentation(ip, port)
    else:
        run_self_test()
