#!/usr/bin/env python3
"""
Debug script to understand the depth calculation mismatch.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import IP, TCP, Raw
from scapy.packet import NoPayload

def test_depth_with_raw():
    """Test depth calculation when Raw layer is present"""
    
    # Test with just IP/TCP
    packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
    print("Packet 1: IP / TCP")
    print(f"Layers: {[layer.__class__.__name__ for layer in packet1.layers()]}")
    
    # Test IP depth in packet1
    ip_layer = packet1[IP]
    depth_below = 0
    cursor = ip_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
        print(f"  IP traversing: {cursor.__class__.__name__}")
    print(f"IP depth_below in packet1: {depth_below}")
    
    # Test with IP/TCP/Raw (which might be added automatically)
    packet2 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443) / Raw(load="test")
    print(f"\nPacket 2: IP / TCP / Raw")
    print(f"Layers: {[layer.__class__.__name__ for layer in packet2.layers()]}")
    
    # Test IP depth in packet2
    ip_layer = packet2[IP]
    depth_below = 0
    cursor = ip_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
        print(f"  IP traversing: {cursor.__class__.__name__}")
    print(f"IP depth_below in packet2: {depth_below}")
    
    # Test TCP depth in packet2
    tcp_layer = packet2[TCP]
    depth_below = 0
    cursor = tcp_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
        print(f"  TCP traversing: {cursor.__class__.__name__}")
    print(f"TCP depth_below in packet2: {depth_below}")

if __name__ == "__main__":
    test_depth_with_raw()
