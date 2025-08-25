#!/usr/bin/env python3
"""
Test the fixed layer weight scaling logic.
"""

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign

class TestScalingCampaign(FuzzingCampaign):
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

def test_scaling_logic():
    print("TESTING FIXED LAYER WEIGHT SCALING LOGIC")
    print("="*60)
    
    for scaling_factor in [0.9, 0.5, 0.1]:
        print(f"\nScaling factor: {scaling_factor}")
        
        campaign = TestScalingCampaign(scaling_factor)
        mutator_mgr = campaign.create_fuzzer()
        packet = campaign.get_packet()
        
        # Test key fields from each layer
        test_cases = [
            (packet[IP], 'src', 'IP layer (depth=2)'),
            (packet[TCP], 'sport', 'TCP layer (depth=1)'),
            (packet[Raw], 'load', 'Raw layer (depth=0)')
        ]
        
        for layer, field_name, description in test_cases:
            base_weight = mutator_mgr.dictionary_manager.get_field_weight(layer, field_name)
            
            # Calculate depth manually for verification
            depth_below = 0
            cursor = layer
            while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
                depth_below += 1
                cursor = cursor.payload
            
            expected_effective = base_weight * (scaling_factor ** depth_below)
            mutation_prob = expected_effective * 100
            
            print(f"  {description}:")
            print(f"    Base weight: {base_weight:.3f}")
            print(f"    Depth below: {depth_below}")
            print(f"    Expected effective: {expected_effective:.6f}")
            print(f"    Mutation probability: {mutation_prob:.1f}%")

    print(f"\nExpected behavior:")
    print(f"  - Lower scaling factors should result in lower mutation rates for outer layers")
    print(f"  - Inner layers (Raw) should be unaffected by scaling")
    print(f"  - With 0.1 scaling, IP layer should have very low mutation rates")
    print(f"  - With 0.9 scaling, IP layer should have moderately reduced mutation rates")

if __name__ == "__main__":
    test_scaling_logic()
