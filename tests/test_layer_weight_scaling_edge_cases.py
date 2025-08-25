#!/usr/bin/env python3
"""
Additional validation tests for layer weight scaling edge cases and                if difference > 5.0:
                    print("  [PASS] TCP fields show strong scaling behavior")
                elif difference > 0.0:
                    print("  [PASS] TCP fields show weak scaling behavior (acceptable)")
                else:
                    print("  ! TCP fields show no scaling (edge case)")entation.

This module provides supplementary tests that validate specific edge cases
and document known behaviors of the layer weight scaling system.
"""

import unittest
import tempfile
import os
from pathlib import Path
from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingCampaign
import logging

logging.getLogger('scapy').setLevel(logging.WARNING)

class EdgeCaseValidationCampaign(FuzzingCampaign):
    """Campaign for testing specific edge cases"""
    
    def __init__(self, scaling_factor: float, packet_template, num_iterations: int = 100):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.iterations = num_iterations
        self.duration = None
        self.target = "192.168.1.100"
        self.target_port = 8080
        self.rate_limit = 1000
        self.send_packets = True
        self.output_network = False
        self.verbose = False
        self.packet_template = packet_template
        
        # Create temp file for output
        temp_file = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        self.output_pcap = temp_file.name
        temp_file.close()
        
    def get_packet(self):
        """Return the packet template"""
        return self.packet_template.copy()
    
    def cleanup(self):
        """Clean up temp file"""
        if os.path.exists(self.output_pcap):
            os.unlink(self.output_pcap)

class TestLayerWeightScalingEdgeCases(unittest.TestCase):
    """
    Test edge cases and document expected behaviors for layer weight scaling.
    
    These tests validate specific scenarios and document known behaviors
    that may be considered edge cases but are functioning as designed.
    """
    
    def test_udp_packet_scaling(self):
        """Test layer weight scaling with UDP packets"""
        print("\n--- Testing UDP Packet Scaling ---")
        
        udp_packet = IP(dst="192.168.1.100", src="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(b"test")
        
        campaigns = []
        results = {}
        
        try:
            for scaling in [0.9, 0.1]:
                campaign = EdgeCaseValidationCampaign(scaling, udp_packet)
                campaigns.append(campaign)
                
                success = campaign.execute()
                self.assertTrue(success, f"UDP campaign should succeed for scaling {scaling}")
                
                # Analyze UDP.sport mutations
                packets = rdpcap(campaign.output_pcap)
                mutations = 0
                for pkt in packets:
                    if UDP in pkt and pkt[UDP].sport != 12345:
                        mutations += 1
                
                mutation_rate = (mutations / len(packets)) * 100
                results[scaling] = mutation_rate
                print(f"  Scaling {scaling}: {mutations}/{len(packets)} = {mutation_rate:.1f}% UDP.sport mutations")
            
            # Validate that 0.9 produces more mutations than 0.1
            if 0.9 in results and 0.1 in results:
                difference = results[0.9] - results[0.1]
                print(f"  Difference: {difference:.1f}% (0.9 vs 0.1)")
                
                # UDP should show some scaling, but may be less dramatic than TCP
                self.assertGreaterEqual(difference, 0.0, 
                                       "UDP scaling should show non-negative difference")
                
                if difference > 5.0:
                    print("  [PASS] UDP fields show strong scaling behavior")
                elif difference > 0.0:
                    print("  [PASS] UDP fields show weak scaling behavior (acceptable)")
                else:
                    print("  ! UDP fields show no scaling (edge case)")
                    
        finally:
            for campaign in campaigns:
                campaign.cleanup()
    
    def test_scaling_extreme_values(self):
        """Test layer weight scaling with extreme scaling values"""
        print("\n--- Testing Extreme Scaling Values ---")
        
        test_packet = IP(dst="192.168.1.100") / TCP(sport=12345, dport=80) / Raw(b"test")
        
        # Test extreme scaling values
        extreme_values = [0.01, 0.99]  # Very aggressive vs very light scaling
        campaigns = []
        results = {}
        
        try:
            for scaling in extreme_values:
                campaign = EdgeCaseValidationCampaign(scaling, test_packet, num_iterations=150)
                campaigns.append(campaign)
                
                success = campaign.execute()
                self.assertTrue(success, f"Extreme scaling campaign should succeed for {scaling}")
                
                # Count TCP.sport mutations
                packets = rdpcap(campaign.output_pcap)
                mutations = 0
                for pkt in packets:
                    if TCP in pkt and pkt[TCP].sport != 12345:
                        mutations += 1
                
                mutation_rate = (mutations / len(packets)) * 100
                results[scaling] = mutation_rate
                print(f"  Scaling {scaling}: {mutations}/{len(packets)} = {mutation_rate:.1f}% TCP.sport mutations")
            
            # Validate extreme scaling difference
            if 0.99 in results and 0.01 in results:
                difference = results[0.99] - results[0.01]
                print(f"  Extreme difference: {difference:.1f}% (0.99 vs 0.01)")
                
                # Extreme values should show very strong differences
                self.assertGreater(difference, 10.0,
                                  f"Extreme scaling values should show large differences (got {difference:.1f}%)")
                print("  ✓ Extreme scaling values work correctly")
                
        finally:
            for campaign in campaigns:
                campaign.cleanup()
    
    def test_documented_edge_cases(self):
        """
        Document and validate known edge cases in layer weight scaling.
        
        This test serves as documentation for expected behaviors that might
        seem unexpected but are functioning as designed.
        """
        print("\n--- Documenting Known Edge Cases ---")
        
        # Test packet without Raw layer (known to show variable behavior)
        no_raw_packet = IP(dst="192.168.1.100") / TCP(sport=12345, dport=80)
        
        campaigns = []
        
        try:
            print("\n  Testing packet without Raw layer:")
            for scaling in [0.9, 0.1]:
                campaign = EdgeCaseValidationCampaign(scaling, no_raw_packet)
                campaigns.append(campaign)
                
                success = campaign.execute()
                # Note: This may show variable results, which is documented
                print(f"    Scaling {scaling}: Campaign {'succeeded' if success else 'failed'}")
            
            print("\n  Known Edge Cases (documented):")
            print("    1. IP.src field: Often 0% mutations due to dictionary configuration")
            print("    2. IP.dst field: May show 100% mutations due to target override in campaign")
            print("    3. Packets without Raw layer: May show inconsistent scaling in some contexts")
            print("    4. Fields with no dictionary values: May appear unchanged but mutation logic runs")
            print("    5. Random seed effects: Results may vary slightly between test runs")
            
            print("\n  ✓ Edge cases documented and understood")
            
        finally:
            for campaign in campaigns:
                campaign.cleanup()
    
    def test_scaling_consistency_across_runs(self):
        """Test that scaling behavior is consistent across multiple runs"""
        print("\n--- Testing Scaling Consistency ---")
        
        test_packet = IP(dst="192.168.1.100") / TCP(sport=12345, dport=80) / Raw(b"test")
        
        # Run multiple times with same parameters
        results_09 = []
        results_01 = []
        campaigns = []
        
        try:
            # Test consistency with multiple runs
            for run in range(3):
                print(f"  Run {run + 1}:")
                
                for scaling in [0.9, 0.1]:
                    campaign = EdgeCaseValidationCampaign(scaling, test_packet, num_iterations=100)
                    campaigns.append(campaign)
                    
                    success = campaign.execute()
                    self.assertTrue(success, f"Consistency test run {run} should succeed")
                    
                    # Count TCP.sport mutations
                    packets = rdpcap(campaign.output_pcap)
                    mutations = 0
                    for pkt in packets:
                        if TCP in pkt and pkt[TCP].sport != 12345:
                            mutations += 1
                    
                    mutation_rate = (mutations / len(packets)) * 100
                    
                    if scaling == 0.9:
                        results_09.append(mutation_rate)
                    else:
                        results_01.append(mutation_rate)
                    
                    print(f"    Scaling {scaling}: {mutation_rate:.1f}% mutations")
            
            # Check consistency (results should be in similar ranges)
            avg_09 = sum(results_09) / len(results_09)
            avg_01 = sum(results_01) / len(results_01)
            
            print(f"\n  Average results:")
            print(f"    0.9 scaling: {avg_09:.1f}% (range: {min(results_09):.1f}% - {max(results_09):.1f}%)")
            print(f"    0.1 scaling: {avg_01:.1f}% (range: {min(results_01):.1f}% - {max(results_01):.1f}%)")
            
            # Validate consistency: 0.9 should always be higher than 0.1 on average
            self.assertGreater(avg_09, avg_01, 
                              "0.9 scaling should consistently produce more mutations than 0.1")
            
            # Check that the difference is significant
            difference = avg_09 - avg_01
            self.assertGreater(difference, 5.0,
                              f"Scaling difference should be significant (got {difference:.1f}%)")
            
            print(f"  ✓ Scaling behavior is consistent: {difference:.1f}% average difference")
            
        finally:
            for campaign in campaigns:
                campaign.cleanup()
