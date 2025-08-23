#!/usr/bin/env python3
"""Test IP.dst behavior specifically with campaign runs"""

import tempfile
import os
from pathlib import Path
from scapy.all import *
from fuzzing_framework import FuzzingCampaign
import logging

logging.getLogger('scapy').setLevel(logging.WARNING)

class IPDstTestCampaign(FuzzingCampaign):
    """Campaign specifically for testing IP.dst behavior"""
    
    def __init__(self, scaling_factor: float, output_file: str):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.iterations = 200  # More samples for better statistics
        self.duration = None
        self.target = "192.168.1.100"  # Same as packet dst to avoid override
        self.target_port = 8080
        self.rate_limit = 1000
        self.send_packets = True
        self.output_network = False
        self.output_pcap = output_file
        self.verbose = False
        
    def get_packet(self):
        """Create test packet"""
        return IP(dst="192.168.1.100", src="10.0.0.1")/TCP(dport=80, sport=12345)

def test_ip_dst_campaign():
    """Test IP.dst with actual campaign runs"""
    
    original_packet = IP(dst="192.168.1.100", src="10.0.0.1")/TCP(dport=80, sport=12345)
    print(f'Original packet: {original_packet.summary()}')
    print(f'Original IP.dst: {original_packet[IP].dst}')
    
    results = {}
    
    for scaling in [0.9, 0.1]:
        print(f'\n=== Testing scaling factor: {scaling} ===')
        
        # Create temp file for PCAP output
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            pcap_file = temp_file.name
        
        try:
            # Create and run campaign
            campaign = IPDstTestCampaign(scaling, pcap_file)
            campaign.execute()
            
            # Analyze results
            if os.path.exists(pcap_file):
                packets = rdpcap(pcap_file)
                print(f'Generated {len(packets)} packets')
                
                # Count IP.dst changes
                dst_changes = 0
                dst_values = set()
                for pkt in packets:
                    if IP in pkt:
                        dst_value = str(pkt[IP].dst)
                        dst_values.add(dst_value)
                        if dst_value != '192.168.1.100':
                            dst_changes += 1
                
                mutation_rate = (dst_changes / len(packets)) * 100
                print(f'IP.dst changes: {dst_changes}/{len(packets)} = {mutation_rate:.1f}%')
                print(f'Unique IP.dst values: {len(dst_values)}')
                print(f'Sample values: {sorted(dst_values)[:10]}')
                
                results[scaling] = {
                    'packets': len(packets),
                    'changes': dst_changes,
                    'rate': mutation_rate,
                    'unique_values': len(dst_values)
                }
            else:
                print('No PCAP file generated!')
                results[scaling] = None
                
        finally:
            # Clean up
            if os.path.exists(pcap_file):
                os.unlink(pcap_file)
    
    # Compare results
    print(f'\n=== COMPARISON ===')
    if results[0.9] and results[0.1]:
        rate_09 = results[0.9]['rate']
        rate_01 = results[0.1]['rate']
        print(f'0.9 scaling: {rate_09:.1f}% IP.dst mutations')
        print(f'0.1 scaling: {rate_01:.1f}% IP.dst mutations')
        print(f'Difference: {rate_09 - rate_01:.1f}% (expect positive for correct scaling)')
        
        if rate_09 > rate_01:
            print('[PASS] CORRECT: 0.9 scaling produces more mutations than 0.1')
        else:
            print('✗ INCORRECT: 0.1 scaling produces more mutations than 0.9')

if __name__ == '__main__':
    test_ip_dst_campaign()
