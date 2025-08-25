#!/usr/bin/env python3
"""
Debug the exact field key construction in dictionary manager.
"""

from scapy.all import *
from dictionary_manager import DictionaryManager
from default_mappings import FIELD_NAME_WEIGHTS

def debug_key_construction():
    print("DEBUGGING KEY CONSTRUCTION IN DICTIONARY MANAGER")
    print("="*60)
    
    dict_mgr = DictionaryManager()
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)/TCP(dport=80, sport=12345)/Raw("Hello World")
    
    # Test what keys are being constructed
    test_fields = ['src', 'dst', 'len', 'ttl']
    
    for field_name in test_fields:
        layer = packet[IP]
        packet_type = type(layer).__name__
        key = f"{packet_type}.{field_name}"
        
        print(f"\nField: {field_name}")
        print(f"  Packet type: {packet_type}")
        print(f"  Constructed key: {key}")
        print(f"  Key in FIELD_NAME_WEIGHTS: {key in FIELD_NAME_WEIGHTS}")
        if key in FIELD_NAME_WEIGHTS:
            print(f"  Expected weight: {FIELD_NAME_WEIGHTS[key]}")
        
        # Get actual weight from dictionary manager
        actual_weight = dict_mgr.get_field_weight(layer, field_name)
        print(f"  Actual weight returned: {actual_weight}")
    
    print(f"\nAll IP-related keys in FIELD_NAME_WEIGHTS:")
    for key, weight in FIELD_NAME_WEIGHTS.items():
        if key.startswith('IP.'):
            print(f"  {key}: {weight}")

if __name__ == "__main__":
    debug_key_construction()
