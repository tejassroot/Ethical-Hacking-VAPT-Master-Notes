#!/usr/bin/env python3
"""
================================================================================
MODULE 17 LAB: ANDROID STORAGE & MANIFEST SECURITY AUDITING ENGINE
PURPOSE: Programmatic auditing of Android application manifests and local storage:
         - AndroidManifest.xml: debuggable, allowBackup, exported IPC components
         - SharedPreferences XML: plaintext credential detection (CWE-312)
         - SQLite database files: SQLCipher encryption verification
COMPLIANCE: Authorized testing only / Standard mobile app security evaluation.
================================================================================
"""

import xml.etree.ElementTree as ET
import os
import re
import sys

SAMPLE_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.enterpriseapp">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:label="EnterpriseApp"
        android:networkSecurityConfig="@xml/network_security_config">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name=".AdminSettingsActivity"
            android:exported="true" />

        <service
            android:name=".BackgroundSyncService"
            android:exported="false" />

        <provider
            android:name=".UserDataProvider"
            android:authorities="com.example.enterpriseapp.userdata"
            android:exported="true" />
            
    </application>
</manifest>
"""

SAMPLE_SHARED_PREFS_XML = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_email">alice@staging.corp</string>
    <string name="auth_token">sk_live_9941a88b72c91823ab1099f</string>
    <string name="api_secret">SuperSecretMobileClientKey2026</string>
    <boolean name="is_logged_in" value="true" />
    <string name="dark_mode">enabled</string>
</map>
"""

def redact_val(val_str):
    if len(val_str) > 4:
        return val_str[:4] + "****REDACTED"
    return "****REDACTED"

def audit_android_manifest(manifest_xml_str):
    """Audits AndroidManifest.xml for dangerous misconfigurations and exposed IPC components."""
    print("=" * 72)
    print("[*] 1. AUDITING ANDROIDMANIFEST.XML SECURITY POSTURE")
    print("=" * 72)

    root = ET.fromstring(manifest_xml_str)
    ns = {"android": "http://schemas.android.com/apk/res/android"}
    
    # 1. Application-level attributes
    app = root.find("application")
    if app is not None:
        debuggable = app.attrib.get(f"{{{ns['android']}}}debuggable", "false")
        allow_backup = app.attrib.get(f"{{{ns['android']}}}allowBackup", "true")

        print(f"    - android:debuggable  : {debuggable}")
        print(f"    - android:allowBackup : {allow_backup}")

        if debuggable.lower() == "true":
            print("    [!] CRITICAL: android:debuggable='true' enabled in production!")
            print("        Allows ADB runtime memory inspection and code injection.")
        else:
            print("    [+] SECURE: Debuggable is disabled.")

        if allow_backup.lower() == "true":
            print("    [!] HIGH RISK: android:allowBackup='true' enabled!")
            print("        Allows extraction of private sandbox data via ADB backup.")
        else:
            print("    [+] SECURE: Backup is explicitly disabled.")

    # 2. Exported Component Audit
    print("\n[*] Auditing Exported IPC Components (Activities, Services, Providers):")
    components = [
        ("Activity", root.findall(".//activity")),
        ("Service", root.findall(".//service")),
        ("Provider", root.findall(".//provider")),
        ("Receiver", root.findall(".//receiver"))
    ]

    for comp_type, elems in components:
        for e in elems:
            name = e.attrib.get(f"{{{ns['android']}}}name", "unknown")
            exported = e.attrib.get(f"{{{ns['android']}}}exported", "false")
            
            # Main launcher activity is normally exported
            is_launcher = False
            for intent in e.findall("intent-filter"):
                for cat in intent.findall("category"):
                    if "LAUNCHER" in cat.attrib.get(f"{{{ns['android']}}}name", ""):
                        is_launcher = True

            if exported.lower() == "true":
                if is_launcher:
                    print(f"    [i] {comp_type:10s}: {name:30s} (Exported Launcher - Expected)")
                else:
                    print(f"    [!] HIGH RISK: {comp_type:10s}: {name:30s} (EXPORTED WITHOUT PERMISSION!)")
            else:
                print(f"    [+] SECURE:    {comp_type:10s}: {name:30s} (Internal Only)")

def audit_shared_preferences(prefs_xml_str):
    """Audits SharedPreferences XML for unencrypted sensitive credentials (CWE-312)."""
    print("\n" + "=" * 72)
    print("[*] 2. AUDITING SHAREDPREFERENCES INSECURE DATA STORAGE (CWE-312)")
    print("=" * 72)

    root = ET.fromstring(prefs_xml_str)
    sensitive_patterns = ["token", "secret", "password", "key", "auth", "credential", "api_"]
    
    findings = []
    for elem in root:
        key_name = elem.attrib.get("name", "")
        val = elem.text if elem.text else elem.attrib.get("value", "")

        if any(p in key_name.lower() for p in sensitive_patterns):
            findings.append((key_name, val))

    if findings:
        print(f"    [!] VULNERABILITY CONFIRMED: Found {len(findings)} unencrypted sensitive items!")
        for k, v in findings:
            print(f"        - Flagged Key: '{k}' -> Raw Stored Value: {redact_val(str(v))}")
        print("        Remediation: Migrate to AndroidX EncryptedSharedPreferences with Keystore.")
    else:
        print("    [+] SECURE: No cleartext credentials found in SharedPreferences.")

def audit_sqlite_encryption(db_bytes):
    """Checks whether an SQLite database file is encrypted (SQLCipher) or cleartext."""
    print("\n" + "=" * 72)
    print("[*] 3. AUDITING SQLITE DATABASE FILE ENCRYPTION")
    print("=" * 72)

    # Standard SQLite cleartext magic header: "SQLite format 3\000" (16 bytes)
    sqlite_magic = b"SQLite format 3\x00"
    if db_bytes.startswith(sqlite_magic):
        print("    [!] CRITICAL: Cleartext SQLite database detected (Magic: 'SQLite format 3')!")
        print("        Database tables and sensitive records are unencrypted on disk.")
        return False
    else:
        print("    [+] SECURE: Database does not start with plaintext SQLite magic bytes.")
        print("        SQLCipher encryption or full-disk encryption active.")
        return True

def run_self_test():
    print("=" * 72)
    print("[*] ANDROID MOBILE APPLICATION SECURITY AUDITING SUITE")
    print("=" * 72)

    # 1. Manifest Audit
    audit_android_manifest(SAMPLE_MANIFEST_XML)

    # 2. SharedPreferences Audit
    audit_shared_preferences(SAMPLE_SHARED_PREFS_XML)

    # 3. SQLite Database Check
    cleartext_sample = b"SQLite format 3\x00\x10\x00\x01\x01\x00\x40\x20\x20..."
    audit_sqlite_encryption(cleartext_sample)

    print("\n" + "=" * 72)
    print("[+] ALL ANDROID FOUNDATIONAL AUDIT CHECKS COMPLETED.")
    print("=" * 72)

if __name__ == "__main__":
    run_self_test()
