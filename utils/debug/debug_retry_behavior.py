#!/usr/bin/env python3
"""
Debug script to check if the retry limit fix is working.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP
from mutator_manager import MutatorManager
import types

# Enable debug logging to see the retry behavior
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

def test_retry_behavior():
    """Test if retry limits are working correctly"""
    
    print("Testing retry behavior with different scaling factors...")
    print("=" * 60)
    
    base_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scaling factor: {scale}")
        print(f"Expected max attempts: {1 if scale < 0.5 else 4}")
        print("-" * 40)
        
        # Create config
        config = types.SimpleNamespace()
        config.layer_weight_scaling = scale
        config.enable_layer_weight_scaling = True
        config.rng = None
        
        # Create mutator manager
        manager = MutatorManager(config)
        
        # Test with single packet to see retry logs
        packets = [base_packet.copy()]
        
        print("Looking for retry attempt logs...")
        fuzzed_packets = manager.fuzz_fields(packets)
        
        print(f"Fuzzing completed for scaling factor {scale}")

if __name__ == "__main__":
    test_retry_behavior()
