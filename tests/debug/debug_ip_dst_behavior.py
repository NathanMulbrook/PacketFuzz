#!/usr/bin/env python3
"""
Debug why IP.dst shows inverted behavior while other fields are correct.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP, Raw
from packetfuzz.mutator_manager import MutatorManager
import types
import random

# Set up debug logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

def debug_ip_dst_behavior():
    """Debug why IP.dst behaves differently"""
    
    print("IP.dst Behavior Debug")
    print("=" * 30)
    
    # Create test packet (same as in the test)
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64) / TCP(dport=80, sport=12345, seq=1000) / Raw("test")
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scale {scale}:")
        print("-" * 20)
        
        # Create config
        config = types.SimpleNamespace()
        config.layer_weight_scaling = scale
        config.enable_layer_weight_scaling = True
        config.rng = random.Random(42)
        config.global_dict_config_path = None
        config.mutator_preference = ['scapy']
        
        # Create mutator manager
        manager = MutatorManager(config)
        
        # Test different IP fields
        test_fields = ['src', 'dst', 'ttl']
        
        for field_name in test_fields:
            # Get field info
            layer = packet[IP]
            field_desc = layer.get_field(field_name)
            
            # Get base weight
            base_weight = manager.dictionary_manager.get_field_weight(layer, field_name)
            
            # Check skip decision
            should_skip = manager._should_skip_field(layer, field_desc, field_name)
            
            print(f"  IP.{field_name}: base_weight={base_weight:.3f}, should_skip={should_skip}")
            
            # Test a few samples to see consistency
            skip_count = 0
            total_samples = 10
            for i in range(total_samples):
                should_skip = manager._should_skip_field(layer, field_desc, field_name)
                if should_skip:
                    skip_count += 1
            
            print(f"    Skip rate: {skip_count}/{total_samples} = {(skip_count/total_samples)*100:.1f}%")

if __name__ == "__main__":
    debug_ip_dst_behavior()
