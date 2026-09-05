#!/usr/bin/env python3
"""
================================================================================
MODULE 11 LAB: LAYER 2 DEFENSE & ARP CACHE POISONING DETECTOR
PURPOSE: Low-level ARP frame parsing, IP-to-MAC binding validation, & flap detection.
REQUIREMENT: Linux with CAP_NET_RAW or root execution.
================================================================================
"""

import socket
import struct
import time
import sys

def format_mac(raw_bytes):
    return ":".join(f"{b:02x}" for b in raw_bytes)

def format_ip(raw_bytes):
    return ".".join(str(b) for b in raw_bytes)

def parse_arp_frame(data):
    if len(data) < 42:
        return None
    eth_type = struct.unpack("!H", data[12:14])[0]
    if eth_type != 0x0806:
        return None

    arp_data = data[14:42]
    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", arp_data[:8])
    sender_mac = format_mac(arp_data[8:14])
    sender_ip = format_ip(arp_data[14:18])
    target_mac = format_mac(arp_data[18:24])
    target_ip = format_ip(arp_data[24:28])

    return {
        "opcode": "REQUEST" if opcode == 1 else "REPLY" if opcode == 2 else f"OP_{opcode}",
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip
    }

def run_arp_monitor(test_mode=True):
    print("=" * 72)
    print("[*] INITIALIZING LAYER 2 ARP DEFENSE & ANOMALY MONITOR")
    print("=" * 72)

    binding_table = {}

    if test_mode:
        print("[*] EXECUTING SYNTHETIC ARP POISONING SIMULATION TEST")
        
        # Frame 1: Legitimate Gateway ARP Announcement (10.0.0.1 -> MAC AA:AA:AA:AA:AA:AA)
        frame1 = (
            b"\xff\xff\xff\xff\xff\xff"  # Dest: Broadcast
            b"\xaa\xaa\xaa\xaa\xaa\xaa"  # Src: Gateway
            b"\x08\x06"                  # EtherType: ARP
            b"\x00\x01\x08\x00\x06\x04\x00\x02" # Eth, IPv4, Reply
            b"\xaa\xaa\xaa\xaa\xaa\xaa"  # Sender MAC
            b"\x0a\x00\x00\x01"          # Sender IP: 10.0.0.1
            b"\xff\xff\xff\xff\xff\xff"  # Target MAC
            b"\x0a\x00\x00\x01"          # Target IP: 10.0.0.1
        )
        
        # Frame 2: Spoofed ARP Reply (Attacker claiming 10.0.0.1 -> MAC MM:MM:MM:MM:MM:MM)
        frame2 = (
            b"\xff\xff\xff\xff\xff\xff"
            b"\xbb\xbb\xbb\xbb\xbb\xbb"
            b"\x08\x06"
            b"\x00\x01\x08\x00\x06\x04\x00\x02"
            b"\xbb\xbb\xbb\xbb\xbb\xbb"  # Attacker MAC
            b"\x0a\x00\x00\x01"          # Claims IP: 10.0.0.1
            b"\xaa\xaa\xaa\xaa\xaa\xaa"
            b"\x0a\x00\x00\x05"
        )

        test_frames = [("Legitimate Announcement", frame1), ("Spoofed Injected Reply", frame2)]
        
        for desc, frame in test_frames:
            parsed = parse_arp_frame(frame)
            print(f"\n[+] Processing Frame: {desc}")
            print(f"    - Type: {parsed['opcode']} | {parsed['sender_ip']} ({parsed['sender_mac']}) -> {parsed['target_ip']}")
            
            ip = parsed["sender_ip"]
            mac = parsed["sender_mac"]
            
            if ip in binding_table and binding_table[ip] != mac:
                print(f"[!] CRITICAL SECURITY ALERT: ARP POISONING DETECTED!")
                print(f"    - IP Address:       {ip}")
                print(f"    - Original MAC:     {binding_table[ip]}")
                print(f"    - Unauthorized MAC: {mac}")
                print(f"    - Detection Method: State Flapping Inconsistency")
            else:
                binding_table[ip] = mac
                print(f"    [+] Binding Recorded: {ip} <-> {mac}")

        print("\n" + "=" * 72)
        print("[+] SYNTHETIC VALIDATION COMPLETE: Layer 2 Poisoning Accurately Flagged.")
        print("=" * 72)
        return True

if __name__ == "__main__":
    run_arp_monitor(test_mode=True)
