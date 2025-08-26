#!/usr/bin/env python3
"""
Debug the layer weight scaling logic to understand what's happening.
"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


import logging
logging.basicConfig(level=logging.DEBUG)

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign

class DebugScalingCampaign(FuzzingCampaign):
    def __init__(self, scaling_factor: float):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.target = "127.0.0.1"
        self.iterations = 5  # Small number for debugging
        self.output_network = False
        self.verbose = False
        
    def get_packet(self):
        return IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)/TCP(dport=80, sport=12345)/Raw("Hello World")

def debug_scaling(scaling_factor):
    print(f"\n{'='*60}")
    print(f"DEBUG: Layer weight scaling = {scaling_factor}")
    print(f"{'='*60}")
    
    campaign = DebugScalingCampaign(scaling_factor)
    mutator_mgr = campaign.create_fuzzer()
    packet = campaign.get_packet()
    
    # Check the actual weights and skip decisions
    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    raw_layer = packet[Raw]
    
    print("Testing skip decisions for each layer (10 trials each):")
    
    for layer_name, layer in [("IP", ip_layer), ("TCP", tcp_layer), ("Raw", raw_layer)]:
        field_name = {"IP": "ttl", "TCP": "dport", "Raw": "load"}[layer_name]
        
        skips = 0
        for i in range(10):
            should_skip = mutator_mgr._should_skip_field(layer, None, field_name)
            if should_skip:
                skips += 1
        
        print(f"  {layer_name} layer ({field_name}): {skips}/10 skips = {skips*10}% skip rate")

if __name__ == "__main__":
    debug_scaling(0.9)
    debug_scaling(0.1)
