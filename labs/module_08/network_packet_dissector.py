#!/usr/bin/env python3
"""
================================================================================
MODULE 08 LAB: RAW PACKET DISSECTOR & TCP STATE ENGINE
PURPOSE: Low-level frame dissection and TCP control flag analysis using raw sockets.
REQUIREMENT: Linux environment with CAP_NET_RAW capability or root execution.
================================================================================
"""

import socket
import struct
import sys
import os

def format_mac(raw_bytes):
    return ":".join(f"{b:02x}" for b in raw_bytes)

def format_ip(raw_bytes):
    return ".".join(str(b) for b in raw_bytes)

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return {
        "dest_mac": format_mac(dest_mac),
        "src_mac": format_mac(src_mac),
        "ethertype": hex(proto),
        "payload": data[14:]
    }

def parse_ipv4_packet(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return {
        "version": version,
        "ihl": ihl,
        "ttl": ttl,
        "protocol": proto,
        "src_ip": format_ip(src),
        "dst_ip": format_ip(target),
        "payload": data[ihl:]
    }

def parse_tcp_segment(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack("! H H I I H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    
    flag_dict = {
        "CWR": bool(flags & 0x0080),
        "ECE": bool(flags & 0x0040),
        "URG": bool(flags & 0x0020),
        "ACK": bool(flags & 0x0010),
        "PSH": bool(flags & 0x0008),
        "RST": bool(flags & 0x0004),
        "SYN": bool(flags & 0x0002),
        "FIN": bool(flags & 0x0001),
    }
    
    active_flags = [k for k, v in flag_dict.items() if v]
    
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": offset,
        "flags": "/".join(active_flags) if active_flags else "NONE",
        "payload": data[offset:]
    }

def test_offline_synthetic_packet():
    """Generates a synthetic Ethernet + IPv4 + TCP SYN packet to verify dissect logic."""
    print("=" * 72)
    print("[*] EXECUTING OFFLINE SYNTHETIC PACKET DISSECTION TEST")
    print("=" * 72)
    
    # 1. Ethernet Header (14 bytes): Dest 00:11:22:33:44:55, Src 66:77:88:99:AA:BB, EtherType 0x0800
    eth_raw = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    
    # 2. IPv4 Header (20 bytes): Version 4, IHL 5 (0x45), TOS 0, Len 40, ID 1234, Flags 0x4000 (DF), TTL 64, Proto 6 (TCP), Cksum 0, Src 192.168.1.10, Dst 192.168.1.254
    ip_raw = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1234, 0x4000, 64, 6, 0, socket.inet_aton("192.168.1.10"), socket.inet_aton("192.168.1.254"))
    
    # 3. TCP Segment (20 bytes): SrcPort 54321, DstPort 443, Seq 100000, Ack 0, Offset 5 (0x5000), Flags SYN (0x0002), Win 65535, Cksum 0, Urg 0
    tcp_raw = struct.pack("!HHIIHHHH", 54321, 443, 100000, 0, (5 << 12) | 0x0002, 65535, 0, 0)
    
    synthetic_frame = eth_raw + ip_raw + tcp_raw
    
    # Dissect
    eth = parse_ethernet_frame(synthetic_frame)
    ipv4 = parse_ipv4_packet(eth["payload"])
    tcp = parse_tcp_segment(ipv4["payload"])
    
    print("[+] Synthetic Dissection Results:")
    print(f"    - Layer 2 Frame:     Src={eth['src_mac']} -> Dst={eth['dest_mac']} (EtherType={eth['ethertype']})")
    print(f"    - Layer 3 IPv4:      Src={ipv4['src_ip']} -> Dst={ipv4['dst_ip']} (TTL={ipv4['ttl']}, Proto={ipv4['protocol']})")
    print(f"    - Layer 4 TCP:       Port={tcp['src_port']} -> DstPort={tcp['dst_port']} | Flags=[{tcp['flags']}]")
    print(f"    - State Tracking:    Seq={tcp['seq']} | Ack={tcp['ack']} | DataOffset={tcp['data_offset']} bytes")
    
    assert eth["dest_mac"] == "00:11:22:33:44:55"
    assert ipv4["src_ip"] == "192.168.1.10"
    assert tcp["dst_port"] == 443
    assert tcp["flags"] == "SYN"
    assert tcp["data_offset"] == 20
    print("\n[+] SYNTHETIC VALIDATION VERIFIED: All parser assertions passed successfully.")
    print("=" * 72)

if __name__ == "__main__":
    test_offline_synthetic_packet()
