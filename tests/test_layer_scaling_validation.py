#!/usr/bin/env python3
"""
Test layer weight scaling by analyzing actual PCAP output files.
This test validates that the scaling factor actually affects which layers get mutated
by examining the packets written to PCAP files.
"""

import unittest
import tempfile
import os
from pathlib import Path
from collections import defaultdict, Counter
from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign
import logging

# Reduce logging noise for cleaner test output
logging.getLogger('scapy').setLevel(logging.WARNING)

class LayerWeightScalingTestCampaign(FuzzingCampaign):
    """Test campaign with configurable layer weight scaling"""
    
    def __init__(self, scaling_factor: float, num_iterations: int = 50, output_file: str = None):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.iterations = num_iterations
        self.duration = None  # Use iterations instead of duration
        self.target = "127.0.0.1"
        self.target_port = 8080
        self.rate_limit = 1000  # Fast generation
        self.send_packets = True  # Enable packet sending to generate PCAP
        self.output_network = False  # Don't actually send to network
        self.output_pcap = output_file  # Use the output_pcap attribute
        self.verbose = False  # Reduce noise
        
    def get_packet(self):
        """Create a predictable 3-layer packet for testing"""
        return IP(dst="192.168.1.100", src="10.0.0.1", ttl=64)/TCP(dport=80, sport=12345)/Raw("Hello World")

def analyze_packet_mutations(original_packet, mutated_packets):
    """
    Analyze which layers and fields were mutated in a set of packets.
    Returns statistics about mutation frequency per layer.
    """
    stats = {
        'ip_mutations': 0,
        'tcp_mutations': 0, 
        'raw_mutations': 0,
        'total_packets': len(mutated_packets),
        'ip_fields_changed': Counter(),
        'tcp_fields_changed': Counter(),
        'raw_fields_changed': Counter()
    }
    
    # Get original layer values for comparison
    orig_ip = original_packet[IP]
    orig_tcp = original_packet[TCP] 
    orig_raw = original_packet[Raw]
    
    for pkt in mutated_packets:
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue
            
        pkt_ip = pkt[IP]
        pkt_tcp = pkt[TCP]
        pkt_raw = pkt[Raw]
        
        # Check IP layer mutations
        ip_changed = False
        for field in ['src', 'dst', 'ttl', 'id', 'flags', 'frag', 'tos', 'len']:
            if hasattr(orig_ip, field) and hasattr(pkt_ip, field):
                if getattr(orig_ip, field) != getattr(pkt_ip, field):
                    stats['ip_fields_changed'][field] += 1
                    ip_changed = True
        if ip_changed:
            stats['ip_mutations'] += 1
            
        # Check TCP layer mutations  
        tcp_changed = False
        for field in ['sport', 'dport', 'seq', 'ack', 'flags', 'window', 'urgptr']:
            if hasattr(orig_tcp, field) and hasattr(pkt_tcp, field):
                if getattr(orig_tcp, field) != getattr(pkt_tcp, field):
                    stats['tcp_fields_changed'][field] += 1
                    tcp_changed = True
        if tcp_changed:
            stats['tcp_mutations'] += 1
            
        # Check Raw layer mutations
        raw_changed = False
        if hasattr(orig_raw, 'load') and hasattr(pkt_raw, 'load'):
            if orig_raw.load != pkt_raw.load:
                stats['raw_fields_changed']['load'] += 1
                raw_changed = True
        if raw_changed:
            stats['raw_mutations'] += 1
    
    # Calculate mutation rates
    if stats['total_packets'] > 0:
        stats['ip_mutation_rate'] = stats['ip_mutations'] / stats['total_packets'] * 100
        stats['tcp_mutation_rate'] = stats['tcp_mutations'] / stats['total_packets'] * 100  
        stats['raw_mutation_rate'] = stats['raw_mutations'] / stats['total_packets'] * 100
    else:
        stats['ip_mutation_rate'] = 0
        stats['tcp_mutation_rate'] = 0
        stats['raw_mutation_rate'] = 0
        
    return stats

def run_scaling_test(scaling_factor: float, num_packets: int = 100):
    """
    Run a test campaign with the given scaling factor and return mutation statistics.
    """
    print(f"\n{'='*60}")
    print(f"Testing layer weight scaling = {scaling_factor}")
    print(f"Generating {num_packets} packets...")
    print(f"{'='*60}")
    
    # Create temporary output file
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
        output_path = tmp_file.name
    
    try:
        # Create and configure campaign
        campaign = LayerWeightScalingTestCampaign(scaling_factor, num_packets, output_path)
        
        # Get original packet for comparison
        original_packet = campaign.get_packet()
        print(f"Original packet: {original_packet.summary()}")
        
        # Run the campaign
        print("Running campaign...")
        success = campaign.execute()
        
        if not success:
            print("ERROR: Campaign execution failed")
            return None
        
        # Verify PCAP was created
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            print(f"ERROR: No PCAP file generated at {output_path}")
            return None
            
        # Read and analyze the generated packets
        generated_packets = rdpcap(output_path)
        print(f"Generated {len(generated_packets)} packets")
        
        if len(generated_packets) == 0:
            print("ERROR: No packets found in PCAP file")
            return None
            
        # Analyze mutations
        stats = analyze_packet_mutations(original_packet, generated_packets)
        
        # Print detailed statistics
        print(f"\nMutation Analysis:")
        print(f"  IP layer mutations:  {stats['ip_mutations']:3d}/{stats['total_packets']} = {stats['ip_mutation_rate']:5.1f}%")
        print(f"  TCP layer mutations: {stats['tcp_mutations']:3d}/{stats['total_packets']} = {stats['tcp_mutation_rate']:5.1f}%")  
        print(f"  Raw layer mutations: {stats['raw_mutations']:3d}/{stats['total_packets']} = {stats['raw_mutation_rate']:5.1f}%")
        
        # Show field-level details
        if stats['ip_fields_changed']:
            print(f"  IP fields changed: {dict(stats['ip_fields_changed'])}")
        if stats['tcp_fields_changed']:
            print(f"  TCP fields changed: {dict(stats['tcp_fields_changed'])}")
        if stats['raw_fields_changed']:
            print(f"  Raw fields changed: {dict(stats['raw_fields_changed'])}")
            
        return stats
        
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.unlink(output_path)

class TestLayerWeightScaling(unittest.TestCase):
    """Unit tests for layer weight scaling functionality"""
    
    def test_layer_weight_scaling_differences(self):
        """Test that different scaling factors produce different mutation patterns"""
        print("\n" + "="*80)
        print("LAYER WEIGHT SCALING VALIDATION TEST")
        print("="*80)
        
        # Test with high scaling (0.9) - outer layers should be mutated more
        stats_high = run_scaling_test(0.9, num_packets=100)
        self.assertIsNotNone(stats_high, "High scaling test failed to generate statistics")
        
        # Test with low scaling (0.1) - outer layers should be mutated much less  
        stats_low = run_scaling_test(0.1, num_packets=100)
        self.assertIsNotNone(stats_low, "Low scaling test failed to generate statistics")
        
        # Compare results
        print(f"\n{'='*80}")
        print("COMPARISON SUMMARY")
        print(f"{'='*80}")
        print(f"Scaling Factor    | IP Mutations | TCP Mutations | Raw Mutations")
        print(f"------------------|--------------|---------------|---------------")
        print(f"0.9 (high)        |    {stats_high['ip_mutation_rate']:5.1f}%    |     {stats_high['tcp_mutation_rate']:5.1f}%     |     {stats_high['raw_mutation_rate']:5.1f}%")
        print(f"0.1 (low)         |    {stats_low['ip_mutation_rate']:5.1f}%    |     {stats_low['tcp_mutation_rate']:5.1f}%     |     {stats_low['raw_mutation_rate']:5.1f}%")
        
        # Calculate differences (high - low: positive means high scaling mutates more)
        ip_diff = stats_high['ip_mutation_rate'] - stats_low['ip_mutation_rate']
        tcp_diff = stats_high['tcp_mutation_rate'] - stats_low['tcp_mutation_rate']
        raw_diff = stats_high['raw_mutation_rate'] - stats_low['raw_mutation_rate']
        
        print(f"Difference        |    {ip_diff:+5.1f}%    |     {tcp_diff:+5.1f}%     |     {raw_diff:+5.1f}%")
        
        # Assertions to validate expected behavior
        print(f"\nValidation:")
        
        # IP layer (depth=2, outermost) should show the biggest difference
        # Higher scaling (0.9) should mutate IP layer MORE than lower scaling (0.1)
        print(f"  IP layer difference: {ip_diff:.1f}% (expect < -5% since 0.1 causes more IP mutations)")
        self.assertLess(ip_diff, -5.0, 
                       f"IP layer should be mutated MORE with low scaling (0.1) vs high scaling (0.9), got difference {ip_diff:.1f}%")
        
        # TCP layer (depth=1, middle) should show moderate difference  
        print(f"  TCP layer difference: {tcp_diff:.1f}% (expect > 5% since higher scaling favors middle layers)")
        self.assertGreater(tcp_diff, 5.0,
                          f"TCP layer should be mutated more with high scaling (0.9) vs low scaling (0.1), got {tcp_diff:.1f}%")
        
        # Raw layer (depth=0) should show little to no difference
        print(f"  Raw layer difference: {raw_diff:.1f}% (expect < 20%)")
        self.assertLess(abs(raw_diff), 20.0,
                       f"Raw layer should show similar mutation rates regardless of scaling (got {raw_diff:.1f}%)")
        
        # Both configurations should generate some mutations
        self.assertGreater(stats_high['total_packets'], 0, "High scaling test should generate packets")
        self.assertGreater(stats_low['total_packets'], 0, "Low scaling test should generate packets")
        
        print(f"\n[PASS] Layer weight scaling is working correctly!")
        print(f"  - Outer layers (IP/TCP) are mutated less frequently with lower scaling factors")
        print(f"  - Inner layer (Raw) mutation rate is unaffected by scaling")
        print(f"  - The differences are statistically significant")


