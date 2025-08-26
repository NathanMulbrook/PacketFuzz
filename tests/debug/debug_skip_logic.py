#!/usr/bin/env python3
"""
Deep debug of the layer weight scaling logic to understand the inversion.
"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


import logging
import random
logging.basicConfig(level=logging.DEBUG)

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign

class DebugSkipLogicCampaign(FuzzingCampaign):
    def __init__(self, scaling_factor: float):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.target = "127.0.0.1"
        self.iterations = 10
        self.output_network = False
        self.verbose = False
        
    def get_packet(self):
        return IP(dst="192.168.1.100", src="10.0.0.1")/TCP(dport=80, sport=12345)/Raw("test")

def debug_skip_logic_detailed(scaling_factor):
    print(f"\n{'='*70}")
    print(f"DETAILED SKIP LOGIC DEBUG: scaling_factor = {scaling_factor}")
    print(f"{'='*70}")
    
    campaign = DebugSkipLogicCampaign(scaling_factor)
    mutator_mgr = campaign.create_fuzzer()
    packet = campaign.get_packet()
    
    # Set deterministic random seed for reproducible results
    random.seed(42)
    mutator_mgr.config.rng = random.Random(42)
    
    # Test IP.src field specifically
    ip_layer = packet[IP]
    field_name = 'src'
    
    print(f"Testing field: IP.{field_name}")
    
    # Get the effective weight calculation manually
    base_weight = mutator_mgr.dictionary_manager.get_field_weight(ip_layer, field_name)
    
    # Calculate depth
    depth_below = 0
    cursor = ip_layer
    while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
        depth_below += 1
        cursor = cursor.payload
    
    effective_weight = base_weight * (scaling_factor ** depth_below)
    
    print(f"  Base weight: {base_weight}")
    print(f"  Depth below: {depth_below}")
    print(f"  Scaling factor: {scaling_factor}")
    print(f"  Effective weight: {effective_weight}")
    print(f"  Skip probability: {(1.0 - effective_weight) * 100:.1f}%")
    
    # Test the should_fuzz logic
    print(f"\nTesting should_fuzz logic (10 trials):")
    skip_count = 0
    for i in range(10):
        # Reset the random generator to a known state for each test
        test_rng = random.Random(42 + i)
        
        # Test should_fuzz directly
        should_fuzz = mutator_mgr.should_fuzz(effective_weight, test_rng)
        should_skip = not should_fuzz
        
        rand_value = test_rng.random()  # This won't be the same as used above, but gives us an idea
        
        print(f"  Trial {i+1}: should_fuzz={should_fuzz}, should_skip={should_skip}")
        
        if should_skip:
            skip_count += 1
    
    actual_skip_rate = skip_count / 10 * 100
    print(f"  Actual skip rate: {actual_skip_rate}%")
    
    # Test _should_skip_field method
    print(f"\nTesting _should_skip_field method (10 trials):")
    skip_count_method = 0
    for i in range(10):
        should_skip = mutator_mgr._should_skip_field(ip_layer, None, field_name)
        if should_skip:
            skip_count_method += 1
        print(f"  Trial {i+1}: _should_skip_field returned {should_skip}")
    
    method_skip_rate = skip_count_method / 10 * 100
    print(f"  Method skip rate: {method_skip_rate}%")

if __name__ == "__main__":
    debug_skip_logic_detailed(0.9)
    debug_skip_logic_detailed(0.1)
