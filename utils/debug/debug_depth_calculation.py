#!/usr/bin/env python3
"""
Debug script to verify depth calculation logic for layer weight scaling.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import IP, TCP
from scapy.packet import NoPayload

def test_depth_calculation():
    """Test the depth calculation logic used in layer weight scaling"""
    
    packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
    
    print("Testing depth calculation for each layer...")
    print("=" * 50)
    
    # Test depth calculation for IP layer
    ip_layer = packet[IP]
    print(f"IP layer: {ip_layer.__class__.__name__}")
    
    # Calculate depth for IP layer
    depth_below = 0
    cursor = ip_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
        print(f"  Found payload: {cursor.__class__.__name__}")
    print(f"  IP depth_below: {depth_below}")
    
    # Test depth calculation for TCP layer  
    tcp_layer = packet[TCP]
    print(f"\nTCP layer: {tcp_layer.__class__.__name__}")
    
    # Calculate depth for TCP layer
    depth_below = 0
    cursor = tcp_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
        print(f"  Found payload: {cursor.__class__.__name__}")
    print(f"  TCP depth_below: {depth_below}")
    
    print("\nExpected scaling calculation:")
    print("For scale = 0.9:")
    print(f"  IP fields (depth=1): base_weight * (0.9 ^ 1) = base_weight * 0.9")
    print(f"  TCP fields (depth=0): base_weight * (0.9 ^ 0) = base_weight * 1.0")
    
    print("\nFor scale = 0.1:")
    print(f"  IP fields (depth=1): base_weight * (0.1 ^ 1) = base_weight * 0.1")  
    print(f"  TCP fields (depth=0): base_weight * (0.1 ^ 0) = base_weight * 1.0")
    
    print("\nSo IP fields should be scaled down more aggressively with lower scaling factors!")

if __name__ == "__main__":
    test_depth_calculation()
