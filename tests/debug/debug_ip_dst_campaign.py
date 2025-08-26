#!/usr/bin/env python3
"""
Test IP.dst specifically in campaign context to find the discrepancy.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from scapy.all import IP, TCP, Raw
import tempfile
from ..test_field_level_scaling import LayerWeightScalingTestCampaign

# Reduce logging noise
logging.basicConfig(level=logging.WARNING)

def test_ip_dst_in_campaign():
    """Test IP.dst behavior specifically in campaign context"""
    
    print("IP.dst Campaign Context Test")
    print("=" * 30)
    
    for scale in [0.9, 0.1]:
        print(f"\nTesting scale {scale}:")
        print("-" * 20)
        
        # Create campaign exactly like in the test
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        campaign = LayerWeightScalingTestCampaign(scale, 20, output_path)  # Small count for speed
        
        # Get the original packet
        original_packet = campaign.get_packet()
        print(f"Original IP.dst: {original_packet[IP].dst}")
        
        # Check the campaign configuration
        print(f"Campaign layer_weight_scaling: {getattr(campaign, 'layer_weight_scaling', 'NOT SET')}")
        print(f"Campaign enable_layer_weight_scaling: {getattr(campaign, 'enable_layer_weight_scaling', 'NOT SET')}")
        
        # Run the campaign
        from packetfuzz.fuzzing_framework import FuzzingFramework
        framework = FuzzingFramework()
        framework.run_campaign(campaign)
        
        # Read and analyze the PCAP
        from scapy.all import rdpcap
        try:
            packets = rdpcap(output_path)
            print(f"Generated {len(packets)} packets")
            
            # Count IP.dst mutations
            original_dst = original_packet[IP].dst
            mutations = 0
            for pkt in packets:
                if IP in pkt and pkt[IP].dst != original_dst:
                    mutations += 1
            
            mutation_rate = (mutations / len(packets)) * 100 if packets else 0
            print(f"IP.dst mutation rate: {mutations}/{len(packets)} = {mutation_rate:.1f}%")
            
        except Exception as e:
            print(f"Error reading PCAP: {e}")
        
        # Clean up
        try:
            os.unlink(output_path)
        except:
            pass

if __name__ == "__main__":
    test_ip_dst_in_campaign()
