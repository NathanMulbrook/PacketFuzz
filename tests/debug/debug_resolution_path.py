#!/usr/bin/env python3
"""
Debug dictionary manager weight resolution path.
"""

from scapy.all import *
from dictionary_manager import DictionaryManager
from default_mappings import FIELD_NAME_WEIGHTS, FIELD_TYPE_WEIGHTS, FIELD_ADVANCED_WEIGHTS

def debug_weight_resolution_path():
    print("DEBUGGING WEIGHT RESOLUTION PATH")
    print("="*50)
    
    dict_mgr = DictionaryManager()
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)
    layer = packet[IP]
    field_name = 'src'
    
    print(f"Testing field: IP.{field_name}")
    
    # Step 1: Check embedded config
    print("\nStep 1: Embedded/inline config")
    has_config = hasattr(packet, 'get_field_fuzz_config')
    print(f"  packet.get_field_fuzz_config exists: {has_config}")
    if has_config:
        field_config = packet.get_field_fuzz_config(field_name)
        print(f"  field_config for '{field_name}': {field_config}")
    
    # Step 2: Advanced mapping 
    print("\nStep 2: Advanced mapping")
    packet_type = type(packet).__name__
    key = f"{packet_type}.{field_name}"
    field_type, properties = dict_mgr._extract_field_info(packet, field_name)
    print(f"  key: {key}")
    print(f"  field_type: {field_type}")
    print(f"  properties: {properties}")
    
    # Check if there's an advanced weight entry
    has_advanced = any(
        entry.get('layer') == packet_type and 
        entry.get('field') == field_name 
        for entry in FIELD_ADVANCED_WEIGHTS
    )
    print(f"  has advanced mapping: {has_advanced}")
    
    # Step 3: Name-based weight
    print("\nStep 3: Name-based weight")
    print(f"  key '{key}' in FIELD_NAME_WEIGHTS: {key in FIELD_NAME_WEIGHTS}")
    if key in FIELD_NAME_WEIGHTS:
        print(f"  expected weight: {FIELD_NAME_WEIGHTS[key]}")
    
    # Step 4: Type-based weight
    print("\nStep 4: Type-based weight")
    print(f"  field_type '{field_type}' in FIELD_TYPE_WEIGHTS: {field_type in FIELD_TYPE_WEIGHTS}")
    if field_type in FIELD_TYPE_WEIGHTS:
        print(f"  type-based weight: {FIELD_TYPE_WEIGHTS[field_type]}")
    
    # Get actual result
    print("\nActual result:")
    actual_weight = dict_mgr.get_field_weight(layer, field_name)
    print(f"  get_field_weight returned: {actual_weight}")

if __name__ == "__main__":
    debug_weight_resolution_path()
