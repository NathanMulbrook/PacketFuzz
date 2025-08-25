#!/usr/bin/env python3
"""
Debug script to test layer weight scaling configuration propagation.
"""

import logging
logging.basicConfig(level=logging.DEBUG)

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign
import tempfile
import os

class DebugLayerScalingCampaign(FuzzingCampaign):
    """Test campaign to debug layer weight scaling"""
    
    def __init__(self, scaling_factor):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        
    def get_packet(self):
        return IP(dst="127.0.0.1")/TCP(dport=80)/Raw("test payload")

import pytest

@pytest.mark.skip(reason="Debug helper not part of automated suite; fixture provided only in notebooks")
def test_scaling_factor(scaling_factor):
    print(f"\n{'='*50}")
    print(f"Testing with scaling_factor = {scaling_factor}")
    print(f"{'='*50}")
    
    # Create campaign with specific scaling factor
    campaign = DebugLayerScalingCampaign(scaling_factor)
    
    # Get mutator manager and check its config
    mutator_mgr = campaign.create_fuzzer()
    
    print(f"Campaign layer_weight_scaling: {campaign.layer_weight_scaling}")
    print(f"MutatorManager config layer_weight_scaling: {mutator_mgr.config.layer_weight_scaling}")
    print(f"MutatorManager config enable_layer_weight_scaling: {mutator_mgr.config.enable_layer_weight_scaling}")
    
    # Test the actual weight calculation
    packet = campaign.get_packet()
    ip_layer = packet[IP]
    tcp_layer = packet[TCP] 
    raw_layer = packet[Raw]
    
    # Check what the mutator thinks it should do for each layer
    ip_skip = mutator_mgr._should_skip_field(ip_layer, None, 'ttl')
    tcp_skip = mutator_mgr._should_skip_field(tcp_layer, None, 'dport') 
    raw_skip = mutator_mgr._should_skip_field(raw_layer, None, 'load')
    
    print(f"IP layer (ttl) should_skip: {ip_skip}")
    print(f"TCP layer (dport) should_skip: {tcp_skip}")
    print(f"Raw layer (load) should_skip: {raw_skip}")
    
    # Run a few iterations to see actual mutations
    print("\nRunning 5 mutations to see if packets change...")
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
        tmp_path = tmp_file.name
    
    try:
        original_packet_str = str(packet)
        unique_packets = set()  # Initialize here
        
        # Run campaign briefly
        campaign.duration = 0.1  # Very short duration
        campaign.output_file = tmp_path
        campaign.target = "127.0.0.1"
        campaign.target_port = 8080
        campaign.rate_limit = 5
        
        print("Running campaign...")
        # This should generate some packets
        # campaign.run()
        
        # Instead of running the full campaign, let's just test mutations directly
        for i in range(5):
            mutated_packets = mutator_mgr.fuzz_packet(packet, iterations=1)
            if mutated_packets:
                mutated_packet = mutated_packets[0]
                mutated_str = str(mutated_packet)
                unique_packets.add(mutated_str)
                if mutated_str != original_packet_str:
                    print(f"  Packet {i+1}: MODIFIED")
                else:
                    print(f"  Packet {i+1}: unchanged")
            else:
                print(f"  Packet {i+1}: no mutation returned")
        
        print(f"Total unique packet variations: {len(unique_packets)}")
        
        print("NOTE: Campaign.run() not tested due to method availability")
            
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
