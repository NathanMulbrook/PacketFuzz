#!/usr/bin/env python3
"""
Debug dictionary manager field weight resolution.
"""

from scapy.all import *
from dictionary_manager import DictionaryManager

def debug_weight_resolution():
    print("DEBUGGING DICTIONARY MANAGER WEIGHT RESOLUTION")
    print("="*60)
    
    dict_mgr = DictionaryManager()
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)/TCP(dport=80, sport=12345)/Raw("Hello World")
    
    # Test key IP fields that should have specific weights
    test_fields = [
        (packet[IP], 'src', 'IP.src should be 0.3'),
        (packet[IP], 'dst', 'IP.dst should be 0.25'), 
        (packet[IP], 'len', 'IP.len should be 0.1'),
        (packet[IP], 'ttl', 'IP.ttl should default to 0.5'),
        (packet[TCP], 'sport', 'TCP.sport should default to 0.5'),
        (packet[TCP], 'dport', 'TCP.dport should default to 0.5'),
    ]
    
    for layer, field_name, description in test_fields:
        weight = dict_mgr.get_field_weight(layer, field_name)
        layer_name = type(layer).__name__
        print(f"{layer_name}.{field_name}: {weight:.3f} ({description})")
    
    print("\nChecking default mappings directly:")
    from default_mappings import FIELD_NAME_WEIGHTS
    for key, weight in FIELD_NAME_WEIGHTS.items():
        if key.startswith('IP.') and key.split('.')[1] in ['src', 'dst', 'len', 'ttl']:
            print(f"  {key}: {weight}")

if __name__ == "__main__":
    debug_weight_resolution()
