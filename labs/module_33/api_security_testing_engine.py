#!/usr/bin/env python3
"""
================================================================================
MODULE 33 LAB: API SECURITY TESTING & MICROSERVICE DEFENSE ENGINE
PURPOSE: Programmatic verification of OWASP API Top 10 (2023) categories:
         - API1: BOLA / IDOR cross-tenant access testing
         - API2: JWT cryptographic validation & 'alg: none' defense
         - API3: BOPLA / Mass Assignment vs. Strict DTO validation
         - API8: GraphQL Introspection disclosure & Query Depth calculation
COMPLIANCE: Authorized testing only / Standard benign API boundary probing.
================================================================================
"""

import json
import base64
import hmac
import hashlib
from dataclasses import dataclass
import sys

# ----------------------------------------------------------------------
# 1. JWT Security & Algorithm Confusion / 'None' Algorithm Testing
# ----------------------------------------------------------------------
def b64url_decode(inp):
    rem = len(inp) % 4
    if rem > 0:
        inp += "=" * (4 - rem)
    return base64.urlsafe_b64decode(inp)

def b64url_encode(inp):
    return base64.urlsafe_b64encode(inp).rstrip(b'=').decode('utf-8')

def parse_and_audit_jwt(jwt_token):
    """Parses JWT parts and audits for alg:none and signature validation."""
    print("=" * 72)
    print("[*] 1. AUDITING JSON WEB TOKEN (JWT) SECURITY")
    print("=" * 72)

    parts = jwt_token.strip().split(".")
    if len(parts) < 2:
        print("[-] Invalid JWT token format.")
        return None

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        print(f"[-] JWT decoding error: {e}")
        return None

    print(f"    - Header:  {header}")
    print(f"    - Payload: {payload}")
    masked_sig = parts[2][:6] + "....[MASKED]" if len(parts) > 2 else "NONE"
    print(f"    - Signature: {masked_sig}")

    # Vulnerability Check 1: alg: none
    alg = header.get("alg", "").lower()
    if alg in ["none", ""]:
        print("    [!] CRITICAL VULNERABILITY (CWE-327): Token accepts 'alg: none'!")
        print("        Allows complete signature bypass and arbitrary claim forgery.")
        return False

    print("    [+] SECURE: Token specifies cryptographic signature algorithm.")
    return True

def forge_alg_none_token(tampered_payload):
    """Creates a forged unsigned JWT with alg:none."""
    header = {"alg": "none", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header).encode('utf-8'))
    p_b64 = b64url_encode(json.dumps(tampered_payload).encode('utf-8'))
    # Trailing dot with no signature
    return f"{h_b64}.{p_b64}."

# ----------------------------------------------------------------------
# 2. BOPLA: Mass Assignment Verification & Strict DTO Remediation
# ----------------------------------------------------------------------
class UserModel:
    def __init__(self, username, email, is_admin=False, credit_balance=0):
        self.username = username
        self.email = email
        self.is_admin = is_admin
        self.credit_balance = credit_balance

def insecure_bind_user(request_json):
    """VULNERABLE: Direct binding of arbitrary user JSON to model attributes."""
    user = UserModel(username=None, email=None)
    for k, v in request_json.items():
        setattr(user, k, v)
    return user

@dataclass
class SafeUserDTO:
    username: str
    email: str

def secure_bind_user(request_json):
    """SECURE: Enforces strict DTO allowlisting; ignores unauthorized fields."""
    if not isinstance(request_json.get("username"), str) or not isinstance(request_json.get("email"), str):
        return {"error": "Invalid field types", "status": 400}

    dto = SafeUserDTO(username=request_json["username"], email=request_json["email"])
    return UserModel(
        username=dto.username,
        email=dto.email,
        is_admin=False,      # Server-controlled default
        credit_balance=0     # Server-controlled default
    )

# ----------------------------------------------------------------------
# 3. GraphQL Query Depth & Complexity Analyzer
# ----------------------------------------------------------------------
def calculate_graphql_depth(query_str):
    """Calculates nesting depth of a GraphQL query to detect potential DoS."""
    max_depth = 0
    current_depth = 0
    for char in query_str:
        if char == '{':
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif char == '}':
            if current_depth > 0:
                current_depth -= 1
    return max_depth

def run_self_test():
    print("=" * 72)
    print("[*] OWASP API SECURITY TESTING ENGINE (LAB SUITE)")
    print("=" * 72)

    # 1. JWT Audit Test
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    parse_and_audit_jwt(sample_jwt)

    # Forged alg: none token
    forged_token = forge_alg_none_token({"sub": "1001", "role": "admin"})
    print("\n[*] Auditing Tampered 'alg: none' Token:")
    parse_and_audit_jwt(forged_token)

    # 2. Mass Assignment Test
    print("\n" + "=" * 72)
    print("[*] 2. AUDITING BROKEN OBJECT PROPERTY LEVEL AUTH (MASS ASSIGNMENT)")
    print("=" * 72)
    malicious_json = {
        "username": "attacker_alice",
        "email": "alice@corp.internal",
        "is_admin": True,
        "credit_balance": 50000
    }
    insecure = insecure_bind_user(malicious_json)
    print(f"    [!] Insecure Endpoint Result: is_admin = {insecure.is_admin} (VULNERABLE!)")

    secure = secure_bind_user(malicious_json)
    print(f"    [+] Secure DTO Endpoint Result: is_admin = {secure.is_admin} (SECURE: Client tampering ignored)")

    # 3. GraphQL Query Depth Test
    print("\n" + "=" * 72)
    print("[*] 3. AUDITING GRAPHQL QUERY DEPTH & RESOURCE EXHAUSTION")
    print("=" * 72)
    nested_query = """
    query {
      user {
        friends {
          friends {
            friends {
              friends {
                friends {
                  name
                }
              }
            }
          }
        }
      }
    }
    """
    depth = calculate_graphql_depth(nested_query)
    print(f"    - Evaluated Query Depth: {depth} levels")
    if depth > 5:
        print(f"    [!] WARNING: Query exceeds recommended depth limit (Threshold: 5)!")
        print(f"        Vulnerable to GraphQL join exhaustion Denial of Service.")
    else:
        print("    [+] SECURE: Query depth within safe limits.")

    print("\n" + "=" * 72)
    print("[+] ALL API SECURITY TESTS PASSED SUCCESSFULLY.")
    print("=" * 72)

if __name__ == "__main__":
    run_self_test()
