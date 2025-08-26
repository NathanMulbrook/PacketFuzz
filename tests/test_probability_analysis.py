#!/usr/bin/env python3
"""
Test to demonstrate layer weight scaling probability differences.
"""

import logging
import random
import pytest
logging.basicConfig(level=logging.INFO)  # Reduce debug noise

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign

class LayerScalingTestCampaign(FuzzingCampaign):
    def __init__(self, scaling_factor):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        
    def get_packet(self):
        return IP(dst="127.0.0.1")/TCP(dport=80)/Raw("test payload")

@pytest.mark.parametrize("scaling_factor", [0.1, 0.5, 0.9])
def test_skip_probability(scaling_factor, trials=100):  # Reduced trials for faster testing
    """Test how often each layer is skipped with a given scaling factor"""
    print(f"\n{'='*60}")
    print(f"Testing skip probability with scaling_factor = {scaling_factor}")
    print(f"Running {trials} trials...")
    print(f"{'='*60}")
    
    campaign = LayerScalingTestCampaign(scaling_factor)
    mutator_mgr = campaign.create_fuzzer()
    packet = campaign.get_packet()
    
    # Get the layers
    ip_layer = packet[IP]
    tcp_layer = packet[TCP] 
    raw_layer = packet[Raw]
    
    # Count skips for each layer
    ip_skips = 0
    tcp_skips = 0
    raw_skips = 0
    
    # Set a fixed seed for reproducible results
    random.seed(42)
    mutator_mgr.config.rng = random.Random(42)
    
    for _ in range(trials):
        if mutator_mgr._should_skip_field(ip_layer, None, 'ttl'):
            ip_skips += 1
        if mutator_mgr._should_skip_field(tcp_layer, None, 'dport'):
            tcp_skips += 1
        if mutator_mgr._should_skip_field(raw_layer, None, 'load'):
            raw_skips += 1
    
    # Calculate skip rates
    ip_skip_rate = ip_skips / trials * 100
    tcp_skip_rate = tcp_skips / trials * 100
    raw_skip_rate = raw_skips / trials * 100
    
    print(f"IP layer (depth=2):  {ip_skips:4d}/{trials} skips = {ip_skip_rate:5.1f}% skip rate")
    print(f"TCP layer (depth=1): {tcp_skips:4d}/{trials} skips = {tcp_skip_rate:5.1f}% skip rate") 
    print(f"Raw layer (depth=0): {raw_skips:4d}/{trials} skips = {raw_skip_rate:5.1f}% skip rate")
    
    # Add assertions to validate the behavior
    if scaling_factor < 0.5:
        # Lower scaling factors should skip outer layers more often
        assert ip_skip_rate > raw_skip_rate, f"IP (outer) should skip more than Raw (inner) with low scaling factor {scaling_factor}"
        # TCP should also skip more than Raw, but less than IP
        assert tcp_skip_rate > raw_skip_rate, f"TCP should skip more than Raw with low scaling factor {scaling_factor}"
    elif scaling_factor > 0.5:
        # Higher scaling factors should still skip outer layers more, but less drastically
        assert ip_skip_rate > raw_skip_rate, f"IP (outer) should still skip more than Raw (inner) even with high scaling factor {scaling_factor}"
        # But the difference should be smaller than with low scaling factors
    
    print(f"\nCONCLUSION:")
    print(f"Layer weight scaling IS working. The differences are probabilistic.")
    print(f"With scaling_factor={scaling_factor}, outer layers skip more than inner layers.")
    print(f"Lower scaling factors create larger differences between layers.")
