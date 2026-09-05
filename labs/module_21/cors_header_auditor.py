#!/usr/bin/env python3
"""
================================================================================
MODULE 21 LAB: CORS MISCONFIGURATION & SECURITY HEADER AUDITOR
PURPOSE: Programmatic probing of CORS reflection, null origins, & cookie flags.
COMPLIANCE: Authorized testing only / Standard benign HTTP header probing.
================================================================================
"""

import urllib.request
import urllib.error
import http.server
import threading
import ssl
import sys
import time

class MockVulnerableServer(http.server.BaseHTTPRequestHandler):
    """Mock HTTP server simulating vulnerable and secure CORS endpoints."""
    def log_message(self, format, *args):
        pass  # Suppress default server access logs in stdout

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        
        # Simulate arbitrary origin reflection with credentials
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
        
        # Missing HSTS and CSP, but includes nosniff
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "user": "alice", "balance": 15000}')

def audit_cors_and_headers(target_url):
    print("=" * 72)
    print(f"[*] AUDITING WEB ARCHITECTURE & CORS SECURITY: {target_url}")
    print("=" * 72)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    test_origins = [
        ("Arbitrary Origin Reflection", "https://attacker.com"),
        ("Null Origin Exploitation",    "null"),
        ("Domain Suffix Matching",      f"{target_url.rstrip('/')}.attacker.com")
    ]

    for test_name, origin in test_origins:
        print(f"\n[*] Testing CORS Vector: {test_name}")
        print(f"    - Injected Origin Header: '{origin}'")
        
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "CORSAuditor/1.0",
                "Origin": origin
            }
        )
        
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                headers = dict(response.info())
                acao = headers.get("Access-Control-Allow-Origin", None)
                acac = headers.get("Access-Control-Allow-Credentials", "false").lower() == "true"
                
                print(f"    - Access-Control-Allow-Origin:      {acao}")
                print(f"    - Access-Control-Allow-Credentials: {acac}")
                
                if acao == origin and acac:
                    print(f"    [!] CRITICAL VULNERABILITY: Arbitrary CORS reflection with credentials enabled!")
                    print(f"        Allows cross-origin data theft from authenticated victim sessions.")
                elif acao == "*" and not acac:
                    print(f"    [i] INFO: Public API Wildcard (*) detected without credentials (Permitted for public data).")
                elif acao is None:
                    print(f"    [+] SECURE: Server did not return permissive CORS headers.")
        except Exception as e:
            print(f"    [*] Probe note: {e}")

    # Baseline Security Headers Check
    print("\n" + "=" * 72)
    print("[*] AUDITING MANDATORY SECURITY DEFENSE HEADERS")
    print("=" * 72)
    
    baseline_req = urllib.request.Request(target_url, headers={"User-Agent": "CORSAuditor/1.0"})
    try:
        with urllib.request.urlopen(baseline_req, timeout=5, context=ctx) as resp:
            h = dict(resp.info())
            checks = {
                "Strict-Transport-Security": "HSTS (Enforces HTTPS transport)",
                "Content-Security-Policy":   "CSP (Mitigates XSS & injection)",
                "X-Content-Type-Options":    "nosniff (Blocks MIME sniffing)",
                "X-Frame-Options":           "Clickjacking defense"
            }
            for hdr, desc in checks.items():
                val = h.get(hdr)
                if val:
                    print(f"    [+] {hdr:28s}: PRESENT ({val[:35]}...)")
                else:
                    print(f"    [!] {hdr:28s}: MISSING ({desc})")
    except Exception as e:
        print(f"[!] Baseline query note: {e}")

    print("\n" + "=" * 72)
    print("[+] WEB ARCHITECTURE AUDIT COMPLETE.")
    print("=" * 72)

def run_self_test():
    print("[*] Starting local mock HTTP server on 127.0.0.1:8889 for verification...")
    server = http.server.HTTPServer(("127.0.0.1", 8889), MockVulnerableServer)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    try:
        audit_cors_and_headers("http://127.0.0.1:8889/api/user/profile")
    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--test":
        target = sys.argv[1]
        audit_cors_and_headers(target)
    else:
        run_self_test()
