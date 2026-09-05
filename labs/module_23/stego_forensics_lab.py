#!/usr/bin/env python3
"""
Digital Steganography, Steganalysis & Forensic Artifacts Verification Engine
Volume 10: Malware, Wireless, IoT & Advanced Security - Module 23
Author: Senior Digital Forensics & Reverse Engineering Specialist

Demonstrates:
1. Synthetic 24-bit uncompressed RGB Bitmap (BMP) creation.
2. Least Significant Bit (LSB) spatial domain payload embedding & extraction.
3. Chi-Square (χ²) statistical steganalysis (Pairs of Values - PoVs analysis).
4. File overlay / trailing slack-space anomaly detection past EOF markers.
5. Cryptographic evidentiary integrity verification via SHA-256 custody hashing.
"""

import struct
import math
import hashlib
import os

def create_synthetic_bmp(width: int = 128, height: int = 128) -> bytearray:
    """
    Constructs a valid 24-bit uncompressed Windows BMP file in memory.
    Header format:
    - BITMAPFILEHEADER (14 bytes): Magic 'BM', FileSize, Reserved, Offset to pixel array (54)
    - BITMAPINFOHEADER (40 bytes): HeaderSize (40), Width, Height, Planes (1), BPP (24), etc.
    """
    row_size = (width * 3 + 3) & ~3  # Row size padded to multiple of 4 bytes
    image_size = row_size * height
    file_size = 54 + image_size

    # 14-byte File Header
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    # 40-byte Info Header
    info_header = struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0, image_size, 2835, 2835, 0, 0)
    
    # Synthetic natural gradient pixel data
    pixels = bytearray()
    for y in range(height):
        row = bytearray()
        for x in range(width):
            # Smooth gradient to simulate natural image characteristics
            r = (x * 2) % 256
            g = (y * 2) % 256
            b = ((x + y)) % 256
            row.extend([b, g, r])
        # Add padding bytes if necessary
        padding = row_size - (width * 3)
        row.extend(b"\x00" * padding)
        pixels.extend(row)

    return bytearray(file_header + info_header + pixels)

def embed_lsb_bmp(bmp_data: bytearray, secret_message: str) -> bytearray:
    """Embeds a null-terminated UTF-8 string into the LSB of BMP pixel bytes."""
    stego_bmp = bytearray(bmp_data)
    pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]
    
    payload_bytes = secret_message.encode('utf-8') + b"\x00"
    payload_bits = []
    for b in payload_bytes:
        for i in range(7, -1, -1):
            payload_bits.append((b >> i) & 1)

    available_capacity = len(bmp_data) - pixel_offset
    if len(payload_bits) > available_capacity:
        raise ValueError(f"Payload requires {len(payload_bits)} bits; carrier capacity is {available_capacity} bits.")

    for idx, bit in enumerate(payload_bits):
        byte_index = pixel_offset + idx
        # Clear the least significant bit (AND 0xFE) and bitwise-OR the secret bit
        stego_bmp[byte_index] = (stego_bmp[byte_index] & 0xFE) | bit

    return stego_bmp

def extract_lsb_bmp(bmp_data: bytearray) -> str:
    """Extracts null-terminated secret string from LSB of BMP pixel bytes."""
    pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]
    extracted_bits = []
    extracted_bytes = bytearray()

    for byte_index in range(pixel_offset, len(bmp_data)):
        bit = bmp_data[byte_index] & 1
        extracted_bits.append(bit)
        if len(extracted_bits) == 8:
            byte_val = 0
            for b in extracted_bits:
                byte_val = (byte_val << 1) | b
            if byte_val == 0:  # Null terminator reached
                break
            extracted_bytes.append(byte_val)
            extracted_bits = []

    return extracted_bytes.decode('utf-8', errors='ignore')

def chi_square_steganalysis(bmp_data: bytearray) -> dict:
    """
    Performs Chi-Square (χ²) statistical steganalysis based on Pairs of Values (PoVs).
    In natural images, adjacent even/odd pixel value counts (2k and 2k+1) vary smoothly.
    LSB embedding equalizes these frequencies towards their arithmetic mean.
    """
    pixel_offset = struct.unpack("<I", bmp_data[10:14])[0]
    raw_pixels = bmp_data[pixel_offset:]
    
    # Calculate frequency of each byte value (0 to 255)
    counts = [0] * 256
    for b in raw_pixels:
        counts[b] += 1

    chi_sq = 0.0
    degrees_of_freedom = 0

    # Evaluate 128 Pairs of Values (PoVs: 2k and 2k+1)
    for k in range(128):
        observed_even = counts[2 * k]
        observed_odd = counts[2 * k + 1]
        expected_mean = (observed_even + observed_odd) / 2.0

        if expected_mean > 5.0:  # Validates statistical sample size threshold
            chi_sq += ((observed_even - expected_mean) ** 2) / expected_mean
            chi_sq += ((observed_odd - expected_mean) ** 2) / expected_mean
            degrees_of_freedom += 1

    # Probability estimation: If chi_sq is very low relative to degrees of freedom,
    # frequencies are artificially equalized (High probability of steganography).
    ratio = chi_sq / max(degrees_of_freedom, 1)
    stego_detected = ratio < 0.5

    return {
        "chi_square_stat": round(chi_sq, 4),
        "degrees_of_freedom": degrees_of_freedom,
        "reduced_chi_square": round(ratio, 4),
        "steganography_detected": stego_detected,
        "confidence": "HIGH" if ratio < 0.3 else ("MODERATE" if ratio < 0.5 else "LOW (Natural Image)")
    }

def audit_file_overlays(carrier_bytes: bytes, format_type: str = "PNG") -> dict:
    """Detects appended data (file overlays) past the formal End-of-File marker."""
    if format_type.upper() == "PNG":
        # PNG End of File Chunk: IEND (0x49 0x45 0x4E 0x44) followed by 4-byte CRC
        iend_signature = b"IEND\xaeB`\x82"
        idx = carrier_bytes.find(iend_signature)
        if idx != -1:
            eof_offset = idx + len(iend_signature)
            overlay_size = len(carrier_bytes) - eof_offset
            if overlay_size > 0:
                return {
                    "has_overlay": True,
                    "eof_offset": eof_offset,
                    "overlay_size_bytes": overlay_size,
                    "overlay_preview": carrier_bytes[eof_offset:eof_offset+32]
                }
    elif format_type.upper() == "JPEG":
        # JPEG End of Image (EOI) Marker: 0xFF 0xD9
        eoi_signature = b"\xff\xd9"
        idx = carrier_bytes.rfind(eoi_signature)
        if idx != -1:
            eof_offset = idx + len(eoi_signature)
            overlay_size = len(carrier_bytes) - eof_offset
            if overlay_size > 0:
                return {
                    "has_overlay": True,
                    "eof_offset": eof_offset,
                    "overlay_size_bytes": overlay_size,
                    "overlay_preview": carrier_bytes[eof_offset:eof_offset+32]
                }
    return {"has_overlay": False, "eof_offset": len(carrier_bytes), "overlay_size_bytes": 0}

if __name__ == "__main__":
    print("=" * 72)
    print("[*] INITIALIZING DIGITAL STEGANOGRAPHY & FORENSIC ARTIFACT AUDIT ENGINE")
    print("=" * 72)

    # 1. Generate Clean Carrier
    clean_bmp = create_synthetic_bmp(width=128, height=128)
    clean_hash = hashlib.sha256(clean_bmp).hexdigest()
    print(f"[+] Created Synthetic 24-bit Clean BMP: {len(clean_bmp)} bytes")
    print(f"    - SHA-256: {clean_hash}")

    # 2. Embed Secret Payload
    secret_data = "CONFIDENTIAL_AUDIT_DATA_2026_TOKEN_MASKED_sk_live_4432****REDACTED"
    stego_bmp = embed_lsb_bmp(clean_bmp, secret_data)
    stego_hash = hashlib.sha256(stego_bmp).hexdigest()
    print(f"\n[+] Embedded Payload via Spatial LSB Modulation: {len(secret_data)} characters")
    print(f"    - SHA-256: {stego_hash}")
    print(f"    - Carrier Visual Integrity: 100% Retained (Imperceptible <0.4% Delta)")

    # 3. Extract Payload
    extracted = extract_lsb_bmp(stego_bmp)
    print(f"\n[+] Extracted Payload from Stego BMP:")
    print(f"    - Payload Content: '{extracted}'")
    assert extracted == secret_data, "Payload verification failed!"
    print("    - Integrity Status: 100% BIT-PERFECT RECONSTRUCTION CONFIRMED")

    # 4. Chi-Square Steganalysis
    print("\n" + "=" * 72)
    print("PHASE 2: STATISTICAL STEGANALYSIS (CHI-SQUARE Pairs-of-Values)")
    print("=" * 72)
    clean_stats = chi_square_steganalysis(clean_bmp)
    print(f"[*] Clean Image Analysis:")
    print(f"    - Chi-Square Stat: {clean_stats['chi_square_stat']}, Reduced: {clean_stats['reduced_chi_square']}")
    print(f"    - Stego Flagged:   {clean_stats['steganography_detected']} ({clean_stats['confidence']})")

    stego_stats = chi_square_steganalysis(stego_bmp)
    print(f"\n[*] Stego Image Analysis:")
    print(f"    - Chi-Square Stat: {stego_stats['chi_square_stat']}, Reduced: {stego_stats['reduced_chi_square']}")
    print(f"    - Stego Flagged:   {stego_stats['steganography_detected']} ({stego_stats['confidence']})")

    # 5. File Overlay / Slack Space Inspection
    print("\n" + "=" * 72)
    print("PHASE 3: FILE OVERLAY & SLACK SPACE ANOMALY AUDITING")
    print("=" * 72)
    synthetic_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20 + b"IEND\xaeB`\x82"
    appended_data = b"HIDDEN_MALICIOUS_STAGE2_ARCHIVE_DATA_OVERLAY"
    tampered_png = synthetic_png + appended_data

    overlay_res = audit_file_overlays(tampered_png, format_type="PNG")
    print(f"[!] Trailing Data / Overlay Audit Result:")
    print(f"    - Overlay Detected:     {overlay_res['has_overlay']}")
    print(f"    - Normal EOF Offset:    0x{overlay_res['eof_offset']:04X}")
    print(f"    - Hidden Overlay Size:  {overlay_res['overlay_size_bytes']} bytes")
    print(f"    - Overlay Preview:      {overlay_res['overlay_preview']}")

    print("\n" + "=" * 72)
    print("[+] DIGITAL STEGANOGRAPHY & FORENSICS LAB COMPLETED SUCCESSFULLY")
    print("=" * 72)
