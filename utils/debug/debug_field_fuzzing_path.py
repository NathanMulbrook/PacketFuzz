#!/usr/bin/env python3
"""
Debug script to trace the exact execution path in _fuzz_field_in_layer.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP, Raw
from mutator_manager import MutatorManager
import types
import random

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

def test_field_fuzzing_path():
    """Test the exact execution path in _fuzz_field_in_layer"""
    
    print("Field Fuzzing Path Debug Test")
    print("=" * 50)
    
    # Create test packet
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64) / TCP(dport=80, sport=12345, seq=1000) / Raw("test")
    
    # Test with scale 0.1 (problematic case)
    config = types.SimpleNamespace()
    config.layer_weight_scaling = 0.1
    config.enable_layer_weight_scaling = True
    config.rng = random.Random(42)
    config.global_dict_config_path = None
    config.mutator_preference = ['scapy']
    
    # Create mutator manager
    manager = MutatorManager(config)
    
    # Now test the actual _fuzz_field_in_layer method for IP.dst
    test_layer = packet[IP] 
    test_field_desc = test_layer.get_field('dst')
    test_field_name = 'dst'
    
    print(f"\nTesting {test_layer.__class__.__name__}.{test_field_name}")
    print("-" * 30)
    
    # Check if field should be skipped
    should_skip = manager._should_skip_field(test_layer, test_field_desc, test_field_name)
    print(f"_should_skip_field result: {should_skip}")
    
    if should_skip:
        print("Field should be skipped, but let's see if _fuzz_field_in_layer agrees...")
    
    # Now test the actual _fuzz_field_in_layer method
    original_value = test_layer.dst
    print(f"Original value: {original_value}")
    
    # Make a copy to test
    test_packet_copy = packet.copy()
    test_layer_copy = test_packet_copy[IP]
    test_field_desc_copy = test_layer_copy.get_field('dst')
    
    result = manager._fuzz_field_in_layer(test_layer_copy, test_field_desc_copy, 'dst')
    print(f"_fuzz_field_in_layer result: {result}")
    print(f"Final value: {test_layer_copy.dst}")
    print(f"Value changed: {original_value != test_layer_copy.dst}")

if __name__ == "__main__":
    test_field_fuzzing_path()
