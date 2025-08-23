#!/usr/bin/env python3
"""Debug script to isolate IP.dst scaling behavior"""

import random
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent))

from fuzzing_framework import FuzzConfig
from mutator_manager import MutatorManager
from dictionary_manager import DictionaryManager
from scapy.layers.inet import IP, TCP
from scapy.all import *

def test_ip_dst_scaling():
    """Test IP.dst field scaling behavior in isolation"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    
    # Create test packet
    packet = IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=143, dport=80, flags='S')
    
    print('=== IP.dst Scaling Debug ===')
    print(f'Original packet: {packet.summary()}')
    
    # Test both scaling factors
    for scaling in [0.9, 0.1]:
        print(f'\n--- Testing scaling factor: {scaling} ---')
        
        # Create new config with different scaling
        config = FuzzConfig()
        config.layer_weight_scaling = scaling
        mm = MutatorManager(config)
        dm = mm.dictionary_manager
        
        # Get base weight
        base_weight = dm.get_field_weight(packet[IP], 'dst')
        depth = 0  # IP is at depth 0
        effective_weight = base_weight * (scaling ** depth)
        
        print(f'Base weight: {base_weight}')
        print(f'Depth: {depth}')
        print(f'Effective weight: {effective_weight}')
        
        # Test skip logic
        skip_count = 0
        mutation_count = 0
        total_tests = 1000
        
        random.seed(42)  # For reproducible results
        
        for i in range(total_tests):
            # Test the actual mutation path
            packet_copy = packet.copy()
            layer = packet_copy[IP]
            
            # Test if field should be skipped
            should_skip = mm._should_skip_field(layer, 'dst')
            
            if should_skip:
                skip_count += 1
            else:
                # Test if mutation actually occurs
                original_value = getattr(layer, 'dst')
                try:
                    mm._fuzz_field_in_layer(layer, 'dst')
                    new_value = getattr(layer, 'dst')
                    if str(original_value) != str(new_value):
                        mutation_count += 1
                except Exception as e:
                    pass  # Mutation failed
        
        skip_rate = (skip_count / total_tests) * 100
        mutation_rate = (mutation_count / total_tests) * 100
        theoretical_rate = ((total_tests - skip_count) / total_tests) * 100
        
        print(f'Skip rate: {skip_count}/{total_tests} = {skip_rate:.1f}%')
        print(f'Theoretical mutation rate: {theoretical_rate:.1f}%')
        print(f'Actual mutation rate: {mutation_rate:.1f}%')
        
        # Check dictionary availability
        dict_values = dm.get_field_values(layer, 'dst')
        print(f'Dictionary values available: {len(dict_values) if dict_values else 0}')

if __name__ == '__main__':
    test_ip_dst_scaling()
