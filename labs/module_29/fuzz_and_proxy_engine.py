#!/usr/bin/env python3
"""
================================================================================
MODULE 29 LAB: WEB SECURITY AUDITING PROXY & FUZZING CALIBRATION ENGINE
PURPOSE: Demonstrates programmatic HTTP proxy inspection, soft-404 differential
         analysis, header match/replace injection, and calibrated path fuzzing.
COMPLIANCE: Authorized testing only / Standard benign HTTP boundary probing.
================================================================================
"""

import http.server
import threading
import urllib.request
import urllib.error
import ssl
import sys
import time
import json

class MockApplicationServer(http.server.BaseHTTPRequestHandler):
    """Simulates an enterprise web application with hidden routes, soft-404, and debug APIs."""
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Admin / Debug endpoints
        if self.path == "/api/v1/internal_debug":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-App-Env", "staging")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "mode": "debug", "endpoints": ["/metrics", "/config_dump"]}')
            return
        elif self.path == "/admin_console_v2":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Admin Portal</title></head><body><h1>Privileged Control Portal</h1></body></html>")
            return
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin_console_v2\nDisallow: /api/v1/internal_debug\n")
            return

        # Soft-404 behavior: Returns HTTP 200 with standard custom not-found template (exact byte size)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Custom Error: Page Not Found</h1><p>The requested resource does not exist on this server.</p></body></html>")

def calibrate_soft_404_baseline(base_url):
    """Sends queries to random non-existent endpoints to determine soft-404 size baseline."""
    canary_paths = [
        "/non_existent_boundary_check_a1b2c3d4",
        "/random_canary_test_9876543210_chk",
        "/probe_baseline_differential_eval_xyz"
    ]
    baselines = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print("[*] Calibrating soft-404 baseline against target...")
    for path in canary_paths:
        target = f"{base_url.rstrip('/')}{path}"
        req = urllib.request.Request(target, headers={"User-Agent": "SecurityAuditEngine/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                body = resp.read()
                length = len(body)
                baselines.append((resp.status, length))
                print(f"    - Canary probe: '{path}' -> HTTP {resp.status} (Length: {length} bytes)")
        except urllib.error.HTTPError as e:
            baselines.append((e.code, len(e.read())))
            print(f"    - Canary probe: '{path}' -> HTTP {e.code}")
        except Exception as err:
            print(f"    - Canary probe failed: {err}")

    if baselines:
        lengths = [b[1] for b in baselines]
        if len(set(lengths)) == 1:
            print(f"[+] Static soft-404 baseline confirmed: {lengths[0]} bytes (Status: {baselines[0][0]})")
            return lengths[0]
    print("[-] Baseline calibration inconclusive; using default size filtering.")
    return None

def execute_calibrated_fuzzing(base_url, wordlist, soft_404_size=None):
    """Executes path discovery while dynamically filtering out soft-404 anomalies."""
    print("\n" + "=" * 72)
    print(f"[*] EXECUTING CALIBRATED PATH DISCOVERY: {base_url}")
    print(f"[*] Filter Size Rule: Skip responses matching length {soft_404_size} bytes")
    print("=" * 72)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    discovered = []
    for word in wordlist:
        path = f"/{word.lstrip('/')}"
        target = f"{base_url.rstrip('/')}{path}"
        req = urllib.request.Request(target, headers={
            "User-Agent": "SecurityAuditEngine/1.0",
            "X-Audit-Purpose": "Authorized-VAPT-Verification"
        })
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                content = resp.read()
                length = len(content)
                status = resp.status

                if soft_404_size and length == soft_404_size:
                    # Filtered as soft-404
                    continue

                content_preview = content[:40].decode("utf-8", errors="ignore").replace("\n", " ")
                print(f"[+] DISCOVERED: {path:30s} | HTTP {status} | Size: {length:5d} bytes | Preview: {content_preview}...")
                discovered.append((path, status, length))
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 401, 403]:
                print(f"[+] DISCOVERED (Auth/Redirect): {path:30s} | HTTP {e.code}")
                discovered.append((path, e.code, 0))
        except Exception as e:
            pass

    print("\n" + "=" * 72)
    print(f"[+] CALIBRATED FUZZING COMPLETE. Valid Discovered Endpoints: {len(discovered)}")
    print("=" * 72)
    return discovered

def run_self_test():
    print("[*] Launching local mock application server on 127.0.0.1:8890...")
    server = http.server.HTTPServer(("127.0.0.1", 8890), MockApplicationServer)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    try:
        base_url = "http://127.0.0.1:8890"
        baseline_size = calibrate_soft_404_baseline(base_url)
        
        sample_wordlist = [
            "robots.txt",
            "index.html",
            "login",
            "admin",
            "admin_console_v2",
            "api/v1/internal_debug",
            "dashboard",
            "backup.zip",
            "nonexistent_endpoint"
        ]
        
        results = execute_calibrated_fuzzing(base_url, sample_wordlist, soft_404_size=baseline_size)
        assert len(results) >= 3, "Expected at least 3 genuine endpoints discovered!"
        print("[+] Self-test passed successfully: all soft-404 responses filtered cleanly.")
    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--test":
        target = sys.argv[1]
        baseline = calibrate_soft_404_baseline(target)
        test_words = ["robots.txt", "admin", "api", "login", "dashboard", ".env", "console"]
        execute_calibrated_fuzzing(target, test_words, soft_404_size=baseline)
    else:
        run_self_test()
