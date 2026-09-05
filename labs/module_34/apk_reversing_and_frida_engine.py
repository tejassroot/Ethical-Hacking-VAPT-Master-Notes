#!/usr/bin/env python3
"""
================================================================================
MODULE 34 LAB: ANDROID APK REVERSE ENGINEERING & FRIDA HOOKING ENGINE
PURPOSE: Programmatic simulation of APK deconstruction, Smali opcode patching,
         hardcoded secret extraction, and automated Frida script synthesis.
COMPLIANCE: Authorized testing only / Standard mobile app binary security analysis.
================================================================================
"""

import re
import sys
import os

SAMPLE_SMALI_CODE = """
.method public static verifyLicenseKey(Ljava/lang/String;)Z
    .registers 3
    .param p0, "key"

    const-string v0, "VALID_PRO_KEY_2026"
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1

    # Insecure branch check: if result is zero (false), jump to license failure
    if-eqz v1, :cond_invalid_license

    const/4 v2, 0x1
    return v2

    :cond_invalid_license
    const/4 v2, 0x0
    return v2
.end method
"""

SAMPLE_DEX_STRINGS = [
    "http://10.0.2.2:8080/api",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.7x91...",
    "sk_live_9941a88b72c91823ab1099f",
    "AKIAIOSFODNN7EXAMPLE",
    "com.target.app.MainActivity",
    "android.intent.action.VIEW"
]

def redact_token(tok):
    if len(tok) > 4:
        return tok[:4] + "****REDACTED"
    return "****REDACTED"

def patch_smali_bytecode(smali_text):
    """
    Simulates reverse-engineering Smali logic inversion:
    Patches `if-eqz` (jump if zero) to `if-nez` (jump if not zero) to bypass check.
    """
    print("=" * 72)
    print("[*] 1. SIMULATING SMALI BYTECODE PATCHING (LOGIC INVERSION)")
    print("=" * 72)

    print("[*] Original Smali Instructions:")
    for line in smali_text.strip().splitlines():
        if "if-eqz" in line or "return" in line:
            print(f"    {line}")

    # Patch opcode
    patched = re.sub(r'\bif-eqz\b', 'if-nez', smali_text)

    print("\n[+] Patched Smali Instructions (Bypass Injected):")
    for line in patched.strip().splitlines():
        if "if-nez" in line or "return" in line:
            print(f"    {line}")

    if "if-nez" in patched:
        print("\n[+] SUCCESS: Conditional branch inverted (if-eqz -> if-nez).")
        print("    Application will now return TRUE even for invalid license keys.")
    return patched

def extract_hardcoded_secrets(string_pool):
    """Scans compiled binary string tables for leaked API keys, tokens, and credentials."""
    print("\n" + "=" * 72)
    print("[*] 2. EXTRACTING HARDCODED SECRETS FROM COMPILED STRING POOL")
    print("=" * 72)

    patterns = [
        ("Stripe/API Key", r'(sk_live_[0-9a-zA-Z]{4})[0-9a-zA-Z]+'),
        ("AWS Access Key", r'(AKIA[0-9A-Z]{4})[0-9A-Z]{12}'),
        ("JWT Auth Token", r'(Bearer\s+eyJ[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-\.]+')
    ]

    discovered = []
    for s in string_pool:
        for name, pat in patterns:
            match = re.search(pat, s)
            if match:
                masked = redact_token(s)
                print(f"    [!] FOUND {name:15s}: {masked}")
                discovered.append((name, masked))

    print(f"\n[+] Total sensitive strings flagged in binary: {len(discovered)}")
    return discovered

def generate_frida_bypass_script():
    """Generates universal Frida dynamic instrumentation script for SSL pinning and root bypass."""
    print("\n" + "=" * 72)
    print("[*] 3. SYNTHESIZING DYNAMIC INSTRUMENTATION SCRIPT (FRIDA)")
    print("=" * 72)

    script_content = """
Java.perform(function() {
    console.log("[*] Injected: Universal SSL Pinning & Root Detection Bypass");

    // 1. Bypass Android X509TrustManager checkServerTrusted
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustAllCerts = Java.registerClass({
        name: 'com.audit.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                console.log("[+] Intercepted checkServerTrusted() -> Bypassed verification!");
            },
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustAllArr = [TrustAllCerts.$new()];
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, TrustAllArr, sr);
    };

    // 2. Bypass Root Detection File Checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/system/bin/su") >= 0 || path.indexOf("magisk") >= 0) {
            console.log("[+] Root detection probe caught on: " + path + " -> Spoofed false");
            return false;
        }
        return this.exists();
    };
});
"""
    print("[+] Generated Frida Script:")
    for line in script_content.strip().splitlines()[:15]:
        print(f"    {line}")
    print("    ... [Script truncated for display] ...")
    return script_content

def run_self_test():
    print("=" * 72)
    print("[*] ANDROID VAPT & REVERSE ENGINEERING AUDITING SUITE")
    print("=" * 72)

    # 1. Patch Smali
    patched_code = patch_smali_bytecode(SAMPLE_SMALI_CODE)
    assert "if-nez" in patched_code, "Smali patching failed!"

    # 2. Extract Secrets
    secrets = extract_hardcoded_secrets(SAMPLE_DEX_STRINGS)
    assert len(secrets) >= 3, "Expected at least 3 hardcoded secrets discovered!"

    # 3. Generate Frida Script
    frida_js = generate_frida_bypass_script()
    assert "TrustAllCerts" in frida_js, "Frida script generation failed!"

    print("\n" + "=" * 72)
    print("[+] ALL ANDROID VAPT & REVERSE ENGINEERING AUDITS PASSED.")
    print("=" * 72)

if __name__ == "__main__":
    run_self_test()
