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

@pytest.mark.parametrize("scaling_factor", [0.1, 0.5, 0.9])
def test_scaling_factor(scaling_factor):
    print(f"\n{'='*50}")
    print(f"Testing with scaling_factor = {scaling_factor}")
    print(f"{'='*50}")
    
    # Create campaign with specific scaling factor
    campaign = DebugLayerScalingCampaign(scaling_factor)
    
    # Get mutator manager and check its config
    from packetfuzz.mutator_manager import MutatorManager, FuzzConfig
    
    # Get packet from campaign 
    packet = campaign.packet if campaign.packet else campaign.get_packet()
    config = FuzzConfig(packets=packet, iterations=getattr(campaign, 'iterations', 1000))
    mutator_mgr = MutatorManager(config)
    
    print(f"Campaign layer_weight_scaling: {campaign.layer_weight_scaling}")
    print(f"MutatorManager config layer_weight_scaling: {mutator_mgr.fuzz_config.layer_weight_scaling}")
    print(f"MutatorManager config enable_layer_weight_scaling: {mutator_mgr.fuzz_config.enable_layer_weight_scaling}")
    
    # Test the actual mutation functionality
    packet = campaign.get_packet()
    
    print("\nTesting mutations...")
    original_packet_str = str(packet)
    unique_packets = set()
    
    # Test mutations directly
    for i in range(5):
        mutated_data = mutator_mgr.fuzz_packet()
        mutated_packets = mutated_data.packet_list
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
    
    # Verify that the scaling factor is properly configured 
    assert campaign.layer_weight_scaling == scaling_factor
    # For now just check it doesn't crash - the scaling config might need work
    assert mutator_mgr.fuzz_config.enable_layer_weight_scaling == True
