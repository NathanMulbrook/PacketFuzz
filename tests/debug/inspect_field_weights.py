#!/usr/bin/env python3
"""
Debug actual field weights to understand why some fields are mutated more than others.
"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign

class WeightInspectionCampaign(FuzzingCampaign):
    def __init__(self, scaling_factor: float):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.target = "127.0.0.1"
        self.iterations = 5
        self.output_network = False
        self.verbose = False
        
    def get_packet(self):
        return IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)/TCP(dport=80, sport=12345)/Raw("Hello World")

def inspect_field_weights(scaling_factor):
    print(f"\n{'='*70}")
    print(f"FIELD WEIGHT INSPECTION: scaling_factor = {scaling_factor}")
    print(f"{'='*70}")
    
    campaign = WeightInspectionCampaign(scaling_factor)
    mutator_mgr = campaign.create_fuzzer()
    packet = campaign.get_packet()
    
    # Check weights for all the fields that were observed to change
    ip_fields = ['src', 'dst', 'ttl', 'id', 'flags', 'frag', 'tos', 'len']
    tcp_fields = ['sport', 'dport', 'seq', 'ack', 'flags', 'window', 'urgptr']
    raw_fields = ['load']
    
    def check_layer_fields(layer_name, layer, fields):
        print(f"\n{layer_name} Layer Fields:")
        for field in fields:
            # Get base weight from dictionary manager
            base_weight = mutator_mgr.dictionary_manager.get_field_weight(layer, field)
            
            # Calculate depth for this layer
            depth_below = 0
            cursor = layer
            while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
                depth_below += 1
                cursor = cursor.payload
            
            # Calculate effective weight with scaling
            if scaling_factor is not None:
                effective_weight = base_weight * (scaling_factor ** depth_below)
            else:
                effective_weight = base_weight
                
            # Calculate skip probability
            skip_prob = (1.0 - effective_weight) * 100
            
            print(f"  {field:>10}: base={base_weight:.3f}, depth={depth_below}, effective={effective_weight:.6f}, skip_prob={skip_prob:5.1f}%")
    
    check_layer_fields("IP", packet[IP], ip_fields)
    check_layer_fields("TCP", packet[TCP], tcp_fields)
    check_layer_fields("Raw", packet[Raw], raw_fields)

if __name__ == "__main__":
    inspect_field_weights(0.9)
    inspect_field_weights(0.1)
