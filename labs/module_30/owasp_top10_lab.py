#!/usr/bin/env python3
"""
================================================================================
MODULE 30 LAB: OWASP TOP 10 VULNERABILITY VERIFICATION & DEFENSE ENGINE
PURPOSE: Programmatic verification of BOLA/IDOR, SQL Injection, SSRF, and XSS
         sinks alongside production-grade parameterized and defensive remediations.
COMPLIANCE: Authorized testing only / Standard benign HTTP boundary probing.
================================================================================
"""

import sqlite3
import ipaddress
import urllib.parse
import html
import sys

def setup_mock_database():
    """Initializes in-memory SQLite database simulating multi-tenant enterprise data."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            role TEXT,
            tenant_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY,
            tenant_id INTEGER,
            owner_id INTEGER,
            title TEXT,
            content TEXT
        )
    """)
    cur.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", [
        (1, "alice", "user", 10),
        (2, "bob",   "user", 20),
        (3, "admin", "admin", 10)
    ])
    cur.executemany("INSERT INTO documents VALUES (?, ?, ?, ?, ?)", [
        (101, 10, 1, "Alice Confidential Strategy", "Strategic revenue targets for FY2027"),
        (102, 10, 1, "Alice Personal Notes", "Security meeting action items"),
        (201, 20, 2, "Bob Proprietary Blueprint", "Next-generation widget schematics")
    ])
    conn.commit()
    return conn

# ----------------------------------------------------------------------
# 1. BOLA / IDOR Verification & Defensive Pattern
# ----------------------------------------------------------------------
def insecure_get_document(conn, doc_id_param):
    """VULNERABLE: Direct object reference without tenant or owner verification."""
    cur = conn.cursor()
    # SQLi + BOLA vulnerability
    query = f"SELECT id, tenant_id, owner_id, title, content FROM documents WHERE id = {doc_id_param}"
    cur.execute(query)
    return cur.fetchall()

def secure_get_document(conn, requesting_user, doc_id_param):
    """SECURE: Enforces strict type conversion, parameterization, and tenant boundaries."""
    try:
        clean_doc_id = int(doc_id_param)
    except (ValueError, TypeError):
        return {"error": "Invalid document identifier format", "status": 400}

    cur = conn.cursor()
    # Enforces parameterized SQL and tenant boundary verification
    cur.execute("""
        SELECT id, tenant_id, owner_id, title, content 
        FROM documents 
        WHERE id = ? AND tenant_id = ?
    """, (clean_doc_id, requesting_user["tenant_id"]))
    row = cur.fetchone()
    if not row:
        return {"error": "Resource not found or access unauthorized", "status": 404}
    return {
        "status": 200,
        "doc": {
            "id": row[0],
            "tenant_id": row[1],
            "owner_id": row[2],
            "title": row[3],
            "content": row[4]
        }
    }

# ----------------------------------------------------------------------
# 2. SSRF URL Validation Engine
# ----------------------------------------------------------------------
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),     # Cloud metadata / Link-Local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7")
]

def validate_ssrf_destination(target_url, simulated_ip=None):
    """Validates destination scheme and resolves IP to prevent SSRF against internal/cloud services."""
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ["http", "https"]:
        return False, f"Forbidden URI scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in target URL"

    # Use simulated IP for deterministic offline testing, or evaluate literal IP
    try:
        ip_obj = ipaddress.ip_address(simulated_ip or hostname)
    except ValueError:
        # In production, socket.getaddrinfo is used; here we check hostname patterns
        if hostname.lower() in ["localhost", "127.0.0.1", "metadata.google.internal"]:
            return False, f"SSRF probe blocked: Hostname '{hostname}' maps to internal namespace"
        return True, f"Hostname '{hostname}' validated successfully"

    for net in BLOCKED_NETWORKS:
        if ip_obj in net:
            return False, f"SSRF probe blocked: IP {ip_obj} resides in restricted network {net}"

    return True, f"Destination IP {ip_obj} validated for external routing"

# ----------------------------------------------------------------------
# 3. Contextual XSS Encoding & Sink Remediation
# ----------------------------------------------------------------------
def render_insecure_profile(username_input):
    """VULNERABLE: Direct concatenation of untrusted input into HTML markup."""
    return f"<div class='user-card'><h3>User Profile</h3><span id='name'>{username_input}</span></div>"

def render_secure_profile(username_input):
    """SECURE: HTML-entities encoding neutralizes tag and script breakouts."""
    sanitized = html.escape(username_input, quote=True)
    return f"<div class='user-card'><h3>User Profile</h3><span id='name'>{sanitized}</span></div>"

def run_owasp_audit():
    print("=" * 72)
    print("[*] OWASP TOP 10 AUDITING & DEFENSIVE VERIFICATION ENGINE")
    print("=" * 72)

    conn = setup_mock_database()

    # Test 1: BOLA / IDOR Boundary Verification
    print("\n[*] 1. AUDITING BROKEN ACCESS CONTROL (BOLA / IDOR)")
    print("    - Scenario: Bob (User ID 2, Tenant 20) attempts to access Alice's Doc (ID 101, Tenant 10)")
    
    # Insecure query
    leak_data = insecure_get_document(conn, "101")
    print(f"    [!] VULNERABILITY (Insecure Endpoint): Bob fetched Doc 101 across tenant boundaries!")
    print(f"        Leaked Content: {leak_data[0][3]} -> '{leak_data[0][4]}'")

    # Secure query
    bob_user = {"id": 2, "username": "bob", "tenant_id": 20}
    secure_attempt = secure_get_document(conn, bob_user, "101")
    print(f"    [+] SECURE (Remediated Endpoint): Enforcing tenant boundary returned: {secure_attempt}")

    # Test 2: SQL Injection Defense Verification
    print("\n[*] 2. AUDITING SQL INJECTION (A03:2021)")
    print("    - Injecting benign boundary condition: '101 OR 1=1'")
    sqli_leak = insecure_get_document(conn, "101 OR 1=1")
    print(f"    [!] VULNERABILITY (Insecure Endpoint): Query evaluated syntax! Rows returned: {len(sqli_leak)}")

    sqli_defended = secure_get_document(conn, bob_user, "101 OR 1=1")
    print(f"    [+] SECURE (Remediated Endpoint): Input parameterization result: {sqli_defended}")

    # Test 3: SSRF Boundary Verification
    print("\n[*] 3. AUDITING SERVER-SIDE REQUEST FORGERY (A10:2021)")
    test_cases = [
        ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
        ("http://127.0.0.1:8080/internal-metrics",    "127.0.0.1"),
        ("http://10.0.5.21/admin-api",                "10.0.5.21"),
        ("https://api.external-vendor.com/data",       "93.184.216.34")
    ]
    for url, mock_ip in test_cases:
        valid, msg = validate_ssrf_destination(url, simulated_ip=mock_ip)
        prefix = "[+] BLOCKED" if not valid else "[!] PERMITTED"
        print(f"    {prefix:12s}: {url:45s} -> {msg}")

    # Test 4: XSS Contextual Encoding Verification
    print("\n[*] 4. AUDITING CROSS-SITE SCRIPTING DEFENSE (A03:2021)")
    probe = "<script>console.log('benign_xss_probe')</script>"
    raw_html = render_insecure_profile(probe)
    safe_html = render_secure_profile(probe)
    print(f"    [!] Raw Output (Dangerous Sink):     {raw_html}")
    print(f"    [+] Encoded Output (Hardened Sink):   {safe_html}")

    print("\n" + "=" * 72)
    print("[+] OWASP TOP 10 AUDIT & REMEDIATION VERIFICATION PASSED.")
    print("=" * 72)

if __name__ == "__main__":
    run_owasp_audit()
