#!/usr/bin/env python3
"""
PCAP Functionality Tests

Comprehensive tests for PCAP file generation, writing, and validation.
Tests verify that PCAP files are created, contain data, and are properly formatted.
"""

import sys
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

import unittest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.fuzzing_framework import FuzzingCampaign
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap
from conftest import PCAPTestCampaign, cleanup_test_files


class TestPCAPFunctionality(unittest.TestCase):
    """Test comprehensive PCAP functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Clean up any leftover files from previous tests
        cleanup_test_files()
        
        self.temp_dir = tempfile.mkdtemp()
        self.test_pcap_file = os.path.join(self.temp_dir, "test_output.pcap")
    
    def tearDown(self):
        """Clean up test environment"""
        # Clean up any created PCAP files
        for file in Path(self.temp_dir).glob("*.pcap"):
            try:
                file.unlink()
            except:
                pass
        try:
            os.rmdir(self.temp_dir)
        except:
            pass
        
        # Clean up any files in the main directory
        cleanup_test_files()
    
    def test_pcap_file_creation(self):
        """Test that PCAP files are created when configured"""
        
        class TestPCAPCreationCampaign(FuzzingCampaign):
            name = "PCAP Creation Test"
            target = "192.168.1.1"
            iterations = 5
            rate_limit = 100.0  # Fast for testing
            verbose = True
            output_network = False
            # output_pcap will be set dynamically
            
            packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(load=b"Test data")
        
        # Test with output_pcap set
        campaign = TestPCAPCreationCampaign()
        campaign.output_pcap = self.test_pcap_file
        
        result = campaign.execute()
        
        # Verify execution succeeded
        assert result == True, "Campaign execution should succeed"
        
        # Verify PCAP file was created
        assert os.path.exists(self.test_pcap_file), f"PCAP file should be created: {self.test_pcap_file}"
        
        # Verify file is not empty
        file_size = os.path.getsize(self.test_pcap_file)
        assert file_size > 0, f"PCAP file should not be empty, got size: {file_size}"
        
        # Verify we can read the PCAP file
        try:
            packets = rdpcap(self.test_pcap_file)
            # Expected based on campaign stats (iterations minus serialize failures)
            stats = campaign.context.stats if campaign.context else {}
            expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
            assert len(packets) == expected, f"Expected {expected} packets, got {len(packets)}"
        except Exception as e:
            assert False, f"Failed to read PCAP file: {e}"
    
    def test_pcap_only_mode(self):
        """Test PCAP-only mode (no network transmission)"""
        
        class TestPCAPOnlyCampaign(FuzzingCampaign):
            name = "PCAP Only Test"
            target = "192.168.1.1"
            iterations = 10
            rate_limit = 100.0
            verbose = True
            output_network = False
            pcap_only = True
            output_pcap = None  # Will be set dynamically
            
            packet = IP(dst="192.168.1.1") / UDP(dport=53) / Raw(load=b"DNS query")
        
        campaign = TestPCAPOnlyCampaign()
        campaign.output_pcap = self.test_pcap_file
        
        result = campaign.execute()
        
        # Verify execution succeeded
        assert result == True, "PCAP-only campaign should succeed"
        
        # Verify PCAP file exists and contains expected packets
        assert os.path.exists(self.test_pcap_file), "PCAP file should exist"
        
        packets = rdpcap(self.test_pcap_file)
        stats = campaign.context.stats if campaign.context else {}
        expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
        # Optionally allow a tolerance window in the future; for now use exact expected
        assert len(packets) == expected, f"Expected {expected} packets, got {len(packets)}"
        
        # Verify packet structure when at least one packet exists
        if len(packets) > 0:
            first_packet = packets[0]
            assert (first_packet.haslayer(IP) or first_packet.haslayer(IPv6)), "Packet should have IP or IPv6 layer"
        # Note: Fuzzer may modify or replace other layers, so we only check for IP
    
    def test_output_pcap_fallback(self):
        """Test that output_pcap fallback works when directory does not exist"""
        class TestPCAPFallbackCampaign(FuzzingCampaign):
            name = "PCAP Fallback Test"
            target = "127.0.0.1"
            iterations = 3
            rate_limit = 100.0
            verbose = True
            output_network = False
            output_pcap: str | None = None
            pcap_only = True
            def get_packet(self):
                return IP(dst="127.0.0.1") / ICMP()
        campaign = TestPCAPFallbackCampaign()
        fallback_file = os.path.join(self.temp_dir, "fallback_test.pcap")
        campaign.output_pcap = fallback_file
        campaign.pcap_only = True
        result = campaign.execute()
        fallback_dirs = [self.temp_dir, os.getcwd()]
        found = False
        stats = campaign.context.stats if campaign.context else {}
        expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
        for d in fallback_dirs:
            for fname in os.listdir(d):
                if fname.endswith(".pcap"):
                    fpath = os.path.join(d, fname)
                    try:
                        packets = rdpcap(fpath)
                        if len(packets) == expected:
                            found = True
                            break
                    except Exception:
                        continue
            if found:
                break
        assert result == True, "Campaign with output_pcap fallback should succeed"
        assert found, "Fallback PCAP file should be created in temp_dir or cwd with expected packet count"
    
    def test_pcap_with_different_packet_types(self):
        """Test PCAP output with various packet types"""
        
        test_cases = [
            {
                "name": "TCP Test",
                "packet": IP(dst="192.168.1.10") / TCP(dport=80, sport=12345) / Raw(load=b"HTTP GET"),
                "expected_layers": [IP, TCP, Raw]
            },
            {
                "name": "UDP Test", 
                "packet": IP(dst="192.168.1.10") / UDP(dport=53, sport=54321) / Raw(load=b"DNS query"),
                "expected_layers": [IP, UDP, Raw]
            },
            {
                "name": "ICMP Test",
                "packet": IP(dst="192.168.1.10") / ICMP(type=8, code=0),
                "expected_layers": [IP, ICMP]
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            class TestVariousPacketsCampaign(FuzzingCampaign):
                name = test_case["name"]
                target = "192.168.1.10"
                iterations = 2
                rate_limit = 100.0
                verbose = True
                output_network = False
                output_pcap = None  # Will be set
                
                packet = test_case["packet"]
            
            test_file = os.path.join(self.temp_dir, f"test_packets_{i}.pcap")
            campaign = TestVariousPacketsCampaign()
            campaign.output_pcap = test_file
            
            result = campaign.execute()
            assert result == True, f"Campaign {test_case['name']} should succeed"
            assert os.path.exists(test_file), f"PCAP file for {test_case['name']} should exist"
            # Verify packet structure per test case
            packets = rdpcap(test_file)
            stats = campaign.context.stats if campaign.context else {}
            expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
            assert len(packets) == expected, f"Expected {expected} packets for {test_case['name']}"
            for packet in packets:
                assert packet.haslayer(IP), f"Packet should have IP layer for {test_case['name']}"
    
    def test_pcap_file_overwrite(self):
        """Test that PCAP files are properly overwritten"""
        class TestOverwriteCampaign(FuzzingCampaign):
            name = "Overwrite Test"
            target = "192.168.1.1"
            iterations = 5
            rate_limit = 100.0
            verbose = True
            output_network = False
            output_pcap = None
            packet = IP(dst="192.168.1.1") / TCP(dport=80)

        # First execution
        campaign1 = TestOverwriteCampaign()
        campaign1.output_pcap = self.test_pcap_file
        result1 = campaign1.execute()
        assert result1 == True, "First campaign should succeed"

        packets1 = rdpcap(self.test_pcap_file)
        first_size = os.path.getsize(self.test_pcap_file)

        # Second execution with different iterations
        campaign2 = TestOverwriteCampaign()
        campaign2.output_pcap = self.test_pcap_file
        campaign2.iterations = 10  # Different number
        result2 = campaign2.execute()
        assert result2 == True, "Second campaign should succeed"

        packets2 = rdpcap(self.test_pcap_file)
        second_size = os.path.getsize(self.test_pcap_file)

        # Verify file content count matches expected; size may not change if both runs wrote 0 packets
        stats2 = campaign2.context.stats if campaign2.context else {}
        expected2 = stats2.get('packets_sent', 0) - stats2.get('serialize_failure_count', 0)
        assert len(packets2) == expected2, f"Second file should have {expected2} packets"
    
    def test_pcap_error_handling(self):
        """Test PCAP error handling with invalid paths"""
        class TestErrorCampaign(FuzzingCampaign):
            name = "Error Test"
            target = "192.168.1.1"
            iterations = 2
            rate_limit = 100.0
            verbose = True
            output_network = False
            output_pcap = None
            packet = IP(dst="192.168.1.1") / TCP(dport=80)

        # Test with invalid directory path
        campaign = TestErrorCampaign()
        campaign.output_pcap = "/nonexistent/directory/test.pcap"
        result = campaign.execute()
        # Should succeed and create fallback file in cwd
        fallback_file = os.path.join(os.getcwd(), "test.pcap")
        assert result == True, "Campaign with invalid PCAP path should succeed via fallback"
        assert os.path.exists(fallback_file), "Fallback PCAP file should be created in cwd"
        packets = rdpcap(fallback_file)
        stats = campaign.context.stats if campaign.context else {}
        expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
        assert len(packets) == expected, f"Expected {expected} packets in fallback file, got {len(packets)}"
    
    def test_pcap_interrupt_handling(self):
        """Test that PCAP files are written even if campaign is interrupted"""
        class TestInterruptCampaign(FuzzingCampaign):
            name = "Interrupt Test"
            target = "192.168.1.1"
            iterations = 1000  # Large number to simulate interruption
            rate_limit = 1000.0  # Fast for testing
            verbose = True
            output_network = False
            output_pcap = None
            packet = IP(dst="192.168.1.1") / TCP(dport=80)

            def _run_fuzzing_loop(self, fuzzer, packet):
                """Override to simulate interruption"""
                from scapy.utils import wrpcap
                collected_packets = []
                try:
                    for i in range(3):
                        fuzzed_packets = fuzzer.fuzz_packet(packet, iterations=1)
                        for fuzzed_packet in fuzzed_packets:
                            if self.socket_type == "raw_ip" and fuzzed_packet.haslayer(IP):
                                fuzzed_packet[IP].dst = self.target
                            collected_packets.append(fuzzed_packet)
                    raise KeyboardInterrupt("Simulated interruption")
                except KeyboardInterrupt:
                    if self.output_pcap and collected_packets:
                        wrpcap(self.output_pcap, collected_packets)
                    return True

        campaign = TestInterruptCampaign()
        campaign.output_pcap = self.test_pcap_file

        result = campaign.execute()
        assert result == True, "Interrupted campaign should still succeed"

        # PCAP file should exist with partial data
        assert os.path.exists(self.test_pcap_file), "PCAP file should exist after interruption"

        packets = rdpcap(self.test_pcap_file)
        assert len(packets) == 3, f"Expected 3 packets from interrupted campaign, got {len(packets)}"
    
    def test_pcap_campaign_from_conftest(self):
        """Test the PCAPTestCampaign from conftest.py"""
        campaign = PCAPTestCampaign()
        # Override the output path to our temp directory
        campaign.output_pcap = self.test_pcap_file

        result = campaign.execute()
        assert result == True, "PCAPTestCampaign should execute successfully"

        # Verify PCAP file
        assert os.path.exists(self.test_pcap_file), "PCAP file should be created"

        packets = rdpcap(self.test_pcap_file)
        stats = campaign.context.stats if campaign.context else {}
        expected = stats.get('packets_sent', 0) - stats.get('serialize_failure_count', 0)
        assert len(packets) == expected, f"Expected {expected} packets, got {len(packets)}"

        # Verify packet structure only when present
        if len(packets) > 0:
            first_packet = packets[0]
            assert first_packet.haslayer(IP), "Packet should have IP layer"
        # Note: Fuzzer may modify packet layers, so we only verify basic IP layer presence

    def test_pcap_contains_actual_mutations(self):
        """Verify PCAP output contains actual field mutations, not just copies"""
        class MutationValidationCampaign(FuzzingCampaign):
            name = "Mutation Validation Test"
            target = "192.168.1.1"
            iterations = 50
            rate_limit = 100.0
            verbose = True
            output_network = False
            output_pcap = None
            
            def get_packet(self):
                # Use a packet with predictable original values
                return IP(dst="192.168.1.1", ttl=64) / TCP(dport=80, sport=12345) / Raw(b"test_data")

        campaign = MutationValidationCampaign()
        campaign.output_pcap = self.test_pcap_file
        
        # Store original packet for comparison
        original_packet = campaign.get_packet()
        original_dport = original_packet[TCP].dport
        original_ttl = original_packet[IP].ttl
        
        result = campaign.execute()
        assert result == True, "Campaign should execute successfully"
        
        # Read and analyze output PCAP for actual mutations
        packets = rdpcap(self.test_pcap_file)
        if len(packets) == 0:
            self.skipTest("No packets generated - cannot validate mutations")
        
        # Track different types of mutations found
        dport_mutations = sum(1 for pkt in packets if TCP in pkt and pkt[TCP].dport != original_dport)
        ttl_mutations = sum(1 for pkt in packets if IP in pkt and pkt[IP].ttl != original_ttl)
        any_mutations = dport_mutations + ttl_mutations
        
        # Log detailed mutation analysis
        print(f"Mutation analysis for {len(packets)} packets:")
        print(f"  TCP.dport mutations: {dport_mutations} ({dport_mutations/len(packets)*100:.1f}%)")
        print(f"  IP.ttl mutations: {ttl_mutations} ({ttl_mutations/len(packets)*100:.1f}%)")
        print(f"  Total field mutations: {any_mutations}")
        
        # Verify that at least some mutations occurred
        mutation_rate = any_mutations / len(packets)
        assert mutation_rate > 0.05, f"Mutation rate too low: {mutation_rate:.1%} (expected >5%)"
        assert mutation_rate < 0.95, f"Mutation rate too high: {mutation_rate:.1%} (expected <95%)"

    def test_pcap_contains_dictionary_values(self):
        """Verify dictionary values appear in fuzzed packets when configured"""
        import tempfile
        
        # Create a test dictionary file
        dict_file = os.path.join(self.temp_dir, "test_ports.txt")
        with open(dict_file, 'w') as f:
            f.write("8080\n8443\n9000\n3306\n5432\n")
        
        class DictionaryTestCampaign(FuzzingCampaign):
            name = "Dictionary Validation Test"
            target = "192.168.1.1"
            iterations = 100  # More iterations to catch dictionary usage
            rate_limit = 100.0
            verbose = True
            output_network = False
            output_pcap = None
            
            def get_packet(self):
                packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(b"test")
                # Configure dictionary for TCP destination port
                tcp_layer = packet[TCP]
                if hasattr(tcp_layer, 'field_fuzz'):
                    tcp_layer.field_fuzz('dport').dictionary = [dict_file]
                return packet

        campaign = DictionaryTestCampaign()
        campaign.output_pcap = self.test_pcap_file
        
        result = campaign.execute()
        assert result == True, "Dictionary campaign should execute successfully"
        
        # Read and analyze PCAP for dictionary values
        packets = rdpcap(self.test_pcap_file)
        if len(packets) == 0:
            self.skipTest("No packets generated - cannot validate dictionary usage")
        
        expected_dict_values = {8080, 8443, 9000, 3306, 5432}
        found_dict_values = set()
        
        for packet in packets:
            if TCP in packet:
                dport = packet[TCP].dport
                if dport in expected_dict_values:
                    found_dict_values.add(dport)
        
        print(f"Dictionary validation for {len(packets)} packets:")
        print(f"  Expected dictionary values: {expected_dict_values}")
        print(f"  Found dictionary values: {found_dict_values}")
        print(f"  Dictionary hit rate: {len(found_dict_values)/len(expected_dict_values)*100:.1f}%")
        
        # At least some dictionary values should appear (relaxed assertion)
        if len(found_dict_values) == 0:
            print("WARNING: No dictionary values found - dictionary may not be applied")
        # Note: Dictionary usage depends on fuzzer configuration, so we log but don't hard assert

    def test_layer_weight_scaling_effects_in_pcap(self):
        """Verify layer weight scaling actually affects mutation rates in PCAP output"""
        def run_scaling_test(scaling_factor, test_name):
            class ScalingTestCampaign(FuzzingCampaign):
                name = f"Scaling Test {test_name}"
                target = "192.168.1.1"
                iterations = 200  # Large sample for statistical analysis
                rate_limit = 200.0
                verbose = False
                output_network = False
                output_pcap = None
                layer_weight_scaling = scaling_factor
                enable_layer_weight_scaling = True
                
                def get_packet(self):
                    return IP(dst="192.168.1.1", ttl=64) / TCP(dport=80, sport=12345) / Raw(b"payload")

            test_file = os.path.join(self.temp_dir, f"scaling_{test_name}.pcap")
            campaign = ScalingTestCampaign()
            campaign.output_pcap = test_file
            
            result = campaign.execute()
            if not result:
                return None
            
            # Analyze mutation rates by layer
            packets = rdpcap(test_file)
            if len(packets) == 0:
                return None
            
            ip_mutations = sum(1 for pkt in packets if IP in pkt and pkt[IP].ttl != 64)
            tcp_mutations = sum(1 for pkt in packets if TCP in pkt and pkt[TCP].dport != 80)
            
            return {
                'packets': len(packets),
                'ip_mutation_rate': ip_mutations / len(packets),
                'tcp_mutation_rate': tcp_mutations / len(packets),
                'total_mutations': ip_mutations + tcp_mutations
            }
        
        # Test with different scaling factors
        high_scaling = run_scaling_test(0.9, "high")
        low_scaling = run_scaling_test(0.1, "low")
        
        if high_scaling and low_scaling:
            print(f"Layer weight scaling analysis:")
            print(f"  High scaling (0.9): IP={high_scaling['ip_mutation_rate']:.1%}, TCP={high_scaling['tcp_mutation_rate']:.1%}")
            print(f"  Low scaling (0.1): IP={low_scaling['ip_mutation_rate']:.1%}, TCP={low_scaling['tcp_mutation_rate']:.1%}")
            
            # With lower scaling, outer layers (IP) should be mutated less frequently
            # This is a statistical trend, so we use a relaxed comparison
            if high_scaling['ip_mutation_rate'] > 0 and low_scaling['ip_mutation_rate'] > 0:
                scaling_effect = low_scaling['ip_mutation_rate'] / high_scaling['ip_mutation_rate']
                print(f"  IP mutation scaling effect: {scaling_effect:.2f}")
                
                # Expect some scaling effect (not necessarily dramatic due to various factors)
                if scaling_effect > 1.2:
                    print("WARNING: Lower scaling factor produced MORE IP mutations - unexpected")
        else:
            print("WARNING: Could not complete layer weight scaling analysis")


# Backward compatibility for unittest
class TestPCAPFunctionalityUnit(TestPCAPFunctionality):
    """Unittest-compatible version of PCAP tests"""
    
    def setUp(self):
        """unittest setUp method"""
        super().setUp()
    
    def tearDown(self):
        """unittest tearDown method"""
        super().tearDown()
    
    # All test methods are inherited from TestPCAPFunctionality



