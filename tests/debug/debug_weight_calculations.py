#!/usr/bin/env python3
"""
Debug the exact weight calculations to find the logic error.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP, Raw
from mutator_manager import MutatorManager
import types
import random

# Set up debug logging to see weight calculations
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

def test_weight_calculations():
    """Test exact weight calculations for different scaling factors"""
    
    print("Weight Calculation Debug Test")
    print("=" * 50)
    
    # Create test packet
    packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64) / TCP(dport=80, sport=12345, seq=1000) / Raw("test")
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scaling factor: {scale}")
        print("-" * 30)
        
        # Create config
        config = types.SimpleNamespace()
        config.layer_weight_scaling = scale
        config.enable_layer_weight_scaling = True
        config.rng = random.Random(42)
        config.global_dict_config_path = None
        config.mutator_preference = ['scapy']
        
        # Create mutator manager
        manager = MutatorManager(config)
        
        # Test weight calculation for specific fields
        test_fields = [
            (packet[IP], 'src'),
            (packet[IP], 'dst'),
            (packet[TCP], 'sport'),
            (packet[TCP], 'seq')
        ]
        
        print("Field weight calculations:")
        for layer, field_name in test_fields:
            # Get base weight
            base_weight = manager.dictionary_manager.get_field_weight(layer, field_name)
            
            # Calculate effective weight manually
            from scapy.packet import NoPayload
            depth_below = 0
            cursor = layer
            while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
                depth_below += 1
                cursor = cursor.payload
            
            effective_weight = base_weight * (float(scale) ** int(max(depth_below, 0)))
            
            # Check skip decision
            should_skip = manager._should_skip_field(layer, layer.get_field(field_name), field_name)
            
            layer_name = getattr(layer, 'name', layer.__class__.__name__)
            print(f"  {layer_name}.{field_name}: base={base_weight:.3f}, depth={depth_below}, effective={effective_weight:.6f}, skip={should_skip}")
        
        # Also test a few actual skip decisions to see randomness
        print("\nActual skip decisions (10 samples):")
        for i in range(10):
            layer = packet[IP]
            field_name = 'src'
            should_skip = manager._should_skip_field(layer, layer.get_field(field_name), field_name)
            print(f"  Sample {i+1}: skip={should_skip}")

if __name__ == "__main__":
    test_weight_calculations()
