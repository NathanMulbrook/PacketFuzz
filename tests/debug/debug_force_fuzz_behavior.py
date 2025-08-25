#!/usr/bin/env python3
"""
Debug script to understand FORCE_FUZZ retry behavior with layer weight scaling.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP
from packetfuzz.fuzzing_framework import FuzzingFramework
from packetfuzz.mutator_manager import MutatorManager
import packetfuzz.default_mappings

# Set up logging to see the debug messages
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

def test_force_fuzz_behavior():
    """Test how FORCE_FUZZ retry mechanism affects layer weight scaling"""
    
    print("Testing FORCE_FUZZ behavior with different scaling factors...")
    print("=" * 60)
    
    base_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scaling factor: {scale}")
        print("-" * 40)
        
        # Create framework with specific scaling
        import types
        config = types.SimpleNamespace()
        config.layer_weight_scaling = scale
        config.enable_layer_weight_scaling = True
        config.packet_count = 5
        config.rng = None
        
        # Create mutator manager with config
        manager = MutatorManager(config)
        
        # Create packets manually to avoid the campaign structure
        packets = [base_packet.copy() for _ in range(5)]
        
        # Count mutations by actually fuzzing
        print("Running fuzzing attempts...")
        mutation_count = {}
        
        for i in range(10):  # 10 attempts to see mutation patterns
            print(f"  Attempt {i+1}: ", end="")
            fuzzed_packets = manager.fuzz_fields(packets)
            
            for pkt in fuzzed_packets:
                # Check which fields were mutated compared to original
                original = base_packet
                if pkt[IP].src != original[IP].src:
                    mutation_count['IP.src'] = mutation_count.get('IP.src', 0) + 1
                    print("IP.src ", end="")
                if pkt[IP].dst != original[IP].dst:
                    mutation_count['IP.dst'] = mutation_count.get('IP.dst', 0) + 1
                    print("IP.dst ", end="")
                if pkt[TCP].sport != original[TCP].sport:
                    mutation_count['TCP.sport'] = mutation_count.get('TCP.sport', 0) + 1
                    print("TCP.sport ", end="")
            print()
        
        print(f"\nMutation counts for scale {scale}:")
        for field, count in mutation_count.items():
            print(f"  {field}: {count}/50 packets ({count*2}%)")
        
        print(f"Total mutations: {sum(mutation_count.values())}")

if __name__ == "__main__":
    test_force_fuzz_behavior()
