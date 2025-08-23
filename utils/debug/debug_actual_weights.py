#!/usr/bin/env python3
"""
Debug specific field weights and mutation behavior to understand the discrepancy.
"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import logging
logging.basicConfig(level=logging.DEBUG)

from scapy.all import *
from fuzzing_framework import FuzzingCampaign

class DebugWeightsCampaign(FuzzingCampaign):
    def __init__(self, scaling_factor: float):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.target = "127.0.0.1"
        self.iterations = 1  # Just one packet
        self.output_network = False
        self.verbose = False
        
    def get_packet(self):
        return IP(dst="192.168.1.100", src="10.0.0.1")/TCP(dport=80, sport=12345)/Raw("test")

def analyze_actual_weights():
    print("ANALYZING ACTUAL FIELD WEIGHTS AND MUTATIONS")
    print("="*60)
    
    for scaling_factor in [0.9, 0.1]:
        print(f"\nScaling factor: {scaling_factor}")
        print("-" * 40)
        
        campaign = DebugWeightsCampaign(scaling_factor)
        mutator_mgr = campaign.create_fuzzer()
        packet = campaign.get_packet()
        
        # Test the fields that are showing high mutation rates
        problematic_fields = [
            (packet[IP], 'src'),
            (packet[IP], 'dst'), 
            (packet[TCP], 'sport'),
        ]
        
        for layer, field_name in problematic_fields:
            layer_name = type(layer).__name__
            
            # Get the actual weights
            base_weight = mutator_mgr.dictionary_manager.get_field_weight(layer, field_name)
            
            # Try to call _should_skip_field multiple times to see the probability distribution
            skip_count = 0
            trials = 100
            
            for _ in range(trials):
                should_skip = mutator_mgr._should_skip_field(layer, None, field_name)
                if should_skip:
                    skip_count += 1
            
            skip_rate = skip_count / trials * 100
            mutation_rate = 100 - skip_rate
            
            print(f"  {layer_name}.{field_name}:")
            print(f"    Base weight: {base_weight:.3f}")
            print(f"    Skip rate: {skip_rate:.1f}% ({skip_count}/{trials})")
            print(f"    Expected mutation rate: {mutation_rate:.1f}%")

if __name__ == "__main__":
    analyze_actual_weights()
