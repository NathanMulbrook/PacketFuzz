#!/usr/bin/env python3
"""
Direct test of layer weight scaling without campaign overhead.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP, Raw
from packetfuzz.mutator_manager import MutatorManager
import types
import random

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')

def test_direct_scaling():
    """Test layer weight scaling directly without campaign"""
    
    print("Direct Layer Weight Scaling Test")
    print("=" * 50)
    
    # Create test packet with Raw layer (like in the test)
    base_packet = IP(dst="192.168.1.100", src="10.0.0.1", ttl=64) / TCP(dport=80, sport=12345, seq=1000) / Raw("test")
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scaling factor: {scale}")
        print("-" * 30)
        
        # Create config
        config = types.SimpleNamespace()
        config.layer_weight_scaling = scale
        config.enable_layer_weight_scaling = True
        config.rng = random.Random(42)  # Fixed seed for reproducibility
        config.global_dict_config_path = None
        config.mutator_preference = ['scapy']
        
        # Create mutator manager
        manager = MutatorManager(config)
        
        # Test multiple packets to get statistics
        mutation_counts = {
            'IP.src': 0,
            'IP.dst': 0,
            'IP.ttl': 0,
            'TCP.sport': 0,
            'TCP.dport': 0,
            'TCP.seq': 0
        }
        
        num_tests = 100
        for i in range(num_tests):
            # Create fresh packet copy
            test_packet = base_packet.copy()
            
            # Fuzz the packet
            fuzzed_packets = manager.fuzz_fields(test_packet, iterations=1)
            fuzzed_pkt = fuzzed_packets[0]
            
            # Check which fields were mutated
            if fuzzed_pkt[IP].src != base_packet[IP].src:
                mutation_counts['IP.src'] += 1
            if fuzzed_pkt[IP].dst != base_packet[IP].dst:
                mutation_counts['IP.dst'] += 1
            if fuzzed_pkt[IP].ttl != base_packet[IP].ttl:
                mutation_counts['IP.ttl'] += 1
            if fuzzed_pkt[TCP].sport != base_packet[TCP].sport:
                mutation_counts['TCP.sport'] += 1
            if fuzzed_pkt[TCP].dport != base_packet[TCP].dport:
                mutation_counts['TCP.dport'] += 1
            if fuzzed_pkt[TCP].seq != base_packet[TCP].seq:
                mutation_counts['TCP.seq'] += 1
        
        # Print results
        print(f"Mutation rates for scale {scale} (out of {num_tests} tests):")
        for field, count in mutation_counts.items():
            rate = (count / num_tests) * 100
            print(f"  {field:>10}: {count:>3}/{num_tests} = {rate:>5.1f}%")
        
        total_mutations = sum(mutation_counts.values())
        print(f"  {'Total':>10}: {total_mutations:>3}/{num_tests * 6} = {(total_mutations/(num_tests*6))*100:>5.1f}%")

if __name__ == "__main__":
    test_direct_scaling()
