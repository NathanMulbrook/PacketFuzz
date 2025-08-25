#!/usr/bin/env python3
"""Debug script to see what actually happens to IP.dst values"""

import random
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent))

from packetfuzz.fuzzing_framework import FuzzConfig
from packetfuzz.mutator_manager import MutatorManager
from scapy.layers.inet import IP, TCP
from scapy.all import *

def test_ip_dst_actual_values():
    """See what actually happens to IP.dst field values"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    
    # Create test packet
    original_packet = IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=143, dport=80, flags='S')
    
    print('=== IP.dst Actual Value Changes ===')
    print(f'Original packet: {original_packet.summary()}')
    print(f'Original IP.dst: {original_packet[IP].dst}')
    
    # Test with 0.9 scaling
    config = FuzzConfig()
    config.layer_weight_scaling = 0.9
    mm = MutatorManager(config)
    
    print(f'\n--- Testing with 0.9 scaling (10 samples) ---')
    for i in range(10):
        packet_copy = original_packet.copy()
        layer = packet_copy[IP]
        
        original_dst = str(layer.dst)
        
        # Test the mutation
        should_skip = mm._should_skip_field(layer, 'dst')
        if not should_skip:
            try:
                field_desc = layer.get_field('dst')
                mm._fuzz_field_in_layer(layer, field_desc, 'dst')
                new_dst = str(layer.dst)
                changed = original_dst != new_dst
                print(f'  Sample {i+1}: {original_dst} -> {new_dst} (changed: {changed})')
            except Exception as e:
                print(f'  Sample {i+1}: {original_dst} -> MUTATION_FAILED ({e})')
        else:
            print(f'  Sample {i+1}: {original_dst} -> SKIPPED')
    
    # Test with 0.1 scaling
    config = FuzzConfig()
    config.layer_weight_scaling = 0.1
    mm = MutatorManager(config)
    
    print(f'\n--- Testing with 0.1 scaling (10 samples) ---')
    for i in range(10):
        packet_copy = original_packet.copy()
        layer = packet_copy[IP]
        
        original_dst = str(layer.dst)
        
        # Test the mutation
        should_skip = mm._should_skip_field(layer, 'dst')
        if not should_skip:
            try:
                field_desc = layer.get_field('dst')
                mm._fuzz_field_in_layer(layer, field_desc, 'dst')
                new_dst = str(layer.dst)
                changed = original_dst != new_dst
                print(f'  Sample {i+1}: {original_dst} -> {new_dst} (changed: {changed})')
            except Exception as e:
                print(f'  Sample {i+1}: {original_dst} -> MUTATION_FAILED ({e})')
        else:
            print(f'  Sample {i+1}: {original_dst} -> SKIPPED')

if __name__ == '__main__':
    random.seed(42)  # For reproducible results
    test_ip_dst_actual_values()
