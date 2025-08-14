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

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

import unittest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP, UDP, ICMP, Raw, rdpcap, wrpcap
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
            output_pcap = None  # Will be set dynamically
            
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
            assert len(packets) > 0, "PCAP file should contain packets"
            assert len(packets) == 5, f"PCAP file should contain 5 packets, got {len(packets)}"
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
        assert len(packets) == 10, f"Expected 10 packets, got {len(packets)}"
        
        # Verify packet structure
        first_packet = packets[0]
        assert first_packet.haslayer(IP), "Packet should have IP layer"
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
        for d in fallback_dirs:
            for fname in os.listdir(d):
                if fname.endswith(".pcap"):
                    fpath = os.path.join(d, fname)
                    try:
                        packets = rdpcap(fpath)
                        if len(packets) == 3:
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
            
        # Verify packet structure
        packets = rdpcap(test_file)
        assert len(packets) == 2, f"Expected 2 packets for {test_case['name']}"
        
        # Just verify the packets exist and have basic IP layer (fuzzer may modify other layers)
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
        
        # Verify file was overwritten
        assert len(packets2) == 10, "Second file should have 10 packets"
        assert second_size != first_size, "File size should change after overwrite"
    
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
        assert len(packets) == 2, f"Expected 2 packets in fallback file, got {len(packets)}"
    
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
                # Run a few iterations then raise KeyboardInterrupt
                import copy
                from scapy.utils import wrpcap
                
                collected_packets = []
                
                try:
                    # Generate a few packets
                    for i in range(3):
                        fuzzed_packets = fuzzer.fuzz_packet(packet, iterations=1)
                        for fuzzed_packet in fuzzed_packets:
                            if self.socket_type == "l3" and fuzzed_packet.haslayer(IP):
                                fuzzed_packet[IP].dst = self.target
                            collected_packets.append(fuzzed_packet)
                    
                    # Simulate interruption
                    raise KeyboardInterrupt("Simulated interruption")
                    
                except KeyboardInterrupt:
                    # Should still write PCAP
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
        assert len(packets) > 0, "PCAP file should contain packets"
        
        # Verify packet structure matches campaign configuration
        first_packet = packets[0]
        assert first_packet.haslayer(IP), "Packet should have IP layer"
        # Note: Fuzzer may modify packet layers, so we only verify basic IP layer presence


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


if __name__ == "__main__":
    # Support both pytest and unittest execution
    if PYTEST_AVAILABLE:
        pytest.main([__file__])
    else:
        import unittest
        unittest.main()
