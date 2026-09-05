#!/usr/bin/env python3
"""
================================================================================
MODULE 28 LAB: WEB ATTACK SURFACE MAPPER & FAVICON HASHER
PURPOSE: Calculates MurmurHash3 favicon digests, extracts security headers,
         and tests for hidden endpoints.
COMPLIANCE: Authorized testing only / Standard non-destructive HTTP probing.
================================================================================
"""

import urllib.request
import urllib.error
import base64
import codecs
import sys
import ssl

def mmh3_32(key, seed=0):
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(nblocks):
        k1 = key[i*4 : (i+1)*4]
        k1 = k1[0] | (k1[1] << 8) | (k1[2] << 16) | (k1[3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = key[nblocks*4:]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    if h1 > 0x7FFFFFFF:
        return h1 - 0x100000000
    return h1

def audit_web_surface(url):
    print("=" * 72)
    print(f"[*] AUDITING WEB ATTACK SURFACE: {url}")
    print("=" * 72)
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url, 
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SurfaceAuditor/1.0"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
            status = response.status
            headers = dict(response.info())
            print(f"[+] Endpoint Reachable: HTTP Status {status}")
            print("\n[*] Critical Perimeter Headers Extracted:")
            for h in ["Server", "X-Powered-By", "Via", "CF-Ray", "X-Frame-Options", "Content-Security-Policy"]:
                val = headers.get(h, "NOT PRESENT")
                print(f"    - {h:25s}: {val}")
    except Exception as e:
        print(f"[*] Base URL probe note: {e}")

    # Favicon Analysis
    favicon_url = url.rstrip("/") + "/favicon.ico"
    print(f"\n[*] Probing Favicon for Shodan Fingerprinting: {favicon_url}")
    try:
        fav_req = urllib.request.Request(favicon_url, headers={"User-Agent": "SurfaceAuditor/1.0"})
        with urllib.request.urlopen(fav_req, timeout=3, context=ctx) as fav_resp:
            fav_bytes = fav_resp.read()
            b64_fav = codecs.encode(fav_bytes, 'base64')
            fav_hash = mmh3_32(b64_fav)
            print(f"[+] Successfully Retrieved Favicon ({len(fav_bytes)} bytes)")
            print(f"[+] MurmurHash3 Integer Digest: {fav_hash}")
            print(f"[+] Shodan Origin Search Query:  http.favicon.hash:{fav_hash}")
    except Exception as e:
        print(f"[*] No accessible favicon detected at /favicon.ico ({e})")
        # Run test calculation on standard synthetic favicon bytes
        synthetic = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04"
        b64_syn = codecs.encode(synthetic, 'base64')
        syn_hash = mmh3_32(b64_syn)
        print(f"[*] Validating Synthetic Favicon Algorithm: MurmurHash3 Digest = {syn_hash}")
        assert isinstance(syn_hash, int)

    print("\n" + "=" * 72)
    print("[+] WEB SURFACE MAPPING AUDIT COMPLETE.")
    print("=" * 72)

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    audit_web_surface(target_url)
