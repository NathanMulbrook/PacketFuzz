#!/usr/bin/env python3
"""
Tests for PCAP-based fuzzing functionality

This module tests the PcapFuzzCampaign class and related utilities.
"""

import unittest
import tempfile
import os
import sys
import shutil
from unittest.mock import patch, MagicMock
from scapy.all import IP, UDP, TCP, Ether, Raw, wrpcap

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapfuzz import PcapFuzzCampaign, pcap_fuzz
from conftest import cleanup_test_files


class TestPcapFuzzCampaign(unittest.TestCase):
    """Test cases for PcapFuzzCampaign class."""
    
    def setUp(self):
        """Set up test environment with temporary files."""
        # Clean up any leftover files from previous tests
        cleanup_test_files()
        
        self.temp_dir = tempfile.mkdtemp()
        self.pcap_file = os.path.join(self.temp_dir, "test.pcap")
        
        # Create test packets
        self.test_packets = [
            IP(dst="192.168.1.1")/UDP(dport=53)/Raw(b"test dns query"),
            IP(dst="192.168.1.2")/TCP(dport=80)/Raw(b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            Ether(dst="aa:bb:cc:dd:ee:ff")/IP(dst="10.0.0.1")/UDP(dport=1234)/Raw(b"custom protocol data")
        ]
        
        # Write test PCAP file
        wrpcap(self.pcap_file, self.test_packets)
    
    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.temp_dir)
        
        # Clean up any files in the main directory
        cleanup_test_files()
    
    def test_campaign_initialization(self):
        """Test that PcapFuzzCampaign initializes correctly."""
        campaign = PcapFuzzCampaign()
        
        # Check default values
        self.assertEqual(campaign.pcap_folder, "regression_samples/")
        self.assertEqual(campaign.fuzz_mode, "field")
        self.assertIsNone(campaign.extract_layer)
        self.assertIsNone(campaign.repackage_in)
        self.assertEqual(campaign.target, "192.168.1.100")
    
    def test_layer_extraction_udp(self):
        """Test UDP layer extraction."""
        campaign = PcapFuzzCampaign()
        
        # Test UDP extraction
        udp_packet = IP()/UDP(dport=53)/Raw(b"test data")
        extracted = campaign._extract_layer(udp_packet, "UDP")
        
        self.assertIsNotNone(extracted)
        self.assertIsInstance(extracted, Raw)
        if extracted:  # Type guard
            self.assertEqual(bytes(extracted), b"test data")
    
    def test_layer_extraction_tcp(self):
        """Test TCP layer extraction."""
        campaign = PcapFuzzCampaign()
        
        # Test TCP extraction  
        tcp_packet = IP()/TCP(dport=80)/Raw(b"HTTP data")
        extracted = campaign._extract_layer(tcp_packet, "TCP")
        
        self.assertIsNotNone(extracted)
        self.assertIsInstance(extracted, Raw)
        if extracted:  # Type guard
            self.assertEqual(bytes(extracted), b"HTTP data")
    
    def test_layer_extraction_ip(self):
        """Test IP layer extraction."""
        campaign = PcapFuzzCampaign()
        
        # Test IP extraction
        eth_packet = Ether()/IP(dst="10.0.0.1")/UDP()/Raw(b"data")
        extracted = campaign._extract_layer(eth_packet, "IP")
        
        self.assertIsNotNone(extracted)
        self.assertIsInstance(extracted, IP)
        if extracted:  # Type guard
            self.assertTrue(extracted.haslayer(UDP))
            self.assertEqual(extracted[IP].dst, "10.0.0.1")
    
    def test_layer_extraction_ethernet(self):
        """Test Ethernet layer extraction."""
        campaign = PcapFuzzCampaign()
        
        # Test Ethernet extraction
        eth_packet = Ether(dst="aa:bb:cc:dd:ee:ff")/IP()/UDP()
        extracted = campaign._extract_layer(eth_packet, "Ethernet")
        
        self.assertIsNotNone(extracted)
        self.assertIsInstance(extracted, Ether)
        if extracted:  # Type guard
            self.assertEqual(extracted[Ether].dst, "aa:bb:cc:dd:ee:ff")
    
    def test_layer_extraction_not_found(self):
        """Test layer extraction when layer is not present."""
        campaign = PcapFuzzCampaign()
        
        # Test non-existent layer
        ip_packet = IP()/UDP()
        extracted = campaign._extract_layer(ip_packet, "TCP")
        
        self.assertIsNone(extracted)
    
    def test_repackage_payload_ip_udp(self):
        """Test payload repackaging with IP/UDP wrapper."""
        campaign = PcapFuzzCampaign()
        campaign.target = "192.168.1.200"
        
        payload = Raw(b"test payload")
        repackaged = campaign._repackage_payload(payload, "IP/UDP")
        
        self.assertTrue(repackaged.haslayer(IP))
        self.assertTrue(repackaged.haslayer(UDP))
        self.assertEqual(repackaged[IP].dst, "192.168.1.200")
        self.assertEqual(repackaged[UDP].dport, 80)
        self.assertEqual(bytes(repackaged[Raw]), b"test payload")
    
    def test_repackage_payload_ip_tcp(self):
        """Test payload repackaging with IP/TCP wrapper."""
        campaign = PcapFuzzCampaign()
        campaign.target = "10.0.0.1"
        
        payload = Raw(b"http data")
        repackaged = campaign._repackage_payload(payload, "IP/TCP")
        
        self.assertTrue(repackaged.haslayer(IP))
        self.assertTrue(repackaged.haslayer(TCP))
        self.assertEqual(repackaged[IP].dst, "10.0.0.1")
        self.assertEqual(repackaged[TCP].dport, 80)
        self.assertEqual(bytes(repackaged[Raw]), b"http data")
    
    def test_repackage_payload_ip_only(self):
        """Test payload repackaging with IP wrapper only."""
        campaign = PcapFuzzCampaign()
        campaign.target = "172.16.0.1"
        
        payload = Raw(b"raw data")
        repackaged = campaign._repackage_payload(payload, "IP")
        
        self.assertTrue(repackaged.haslayer(IP))
        self.assertEqual(repackaged[IP].dst, "172.16.0.1")
        self.assertEqual(bytes(repackaged[Raw]), b"raw data")
    
    def test_repackage_payload_no_wrapper(self):
        """Test payload repackaging with unknown wrapper."""
        campaign = PcapFuzzCampaign()
        
        payload = Raw(b"unchanged")
        repackaged = campaign._repackage_payload(payload, "UNKNOWN")
        
        self.assertEqual(repackaged, payload)
    
    def test_convert_to_scapy_ip(self):
        """Test conversion of bytes to Scapy IP packet."""
        campaign = PcapFuzzCampaign()
        
        # Create IP packet bytes
        ip_packet = IP(dst="192.168.1.1")/UDP()
        ip_bytes = bytes(ip_packet)
        
        converted = campaign._convert_to_scapy(ip_bytes)
        self.assertIsInstance(converted, IP)
    
    def test_convert_to_scapy_raw_fallback(self):
        """Test conversion of non-IP bytes to Raw packet."""
        campaign = PcapFuzzCampaign()
        
        # Use invalid IP data
        invalid_data = b"not ip data"
        converted = campaign._convert_to_scapy(invalid_data)
        
        self.assertIsInstance(converted, Raw)
        self.assertEqual(bytes(converted), invalid_data)
    
    def test_process_packet_no_extraction(self):
        """Test packet processing without layer extraction."""
        campaign = PcapFuzzCampaign()
        
        original = IP()/UDP()/Raw(b"data")
        processed = campaign._process_packet(original)
        
        self.assertEqual(processed, original)
    
    def test_process_packet_with_extraction(self):
        """Test packet processing with layer extraction."""
        campaign = PcapFuzzCampaign()
        campaign.extract_layer = "UDP"
        
        original = IP()/UDP()/Raw(b"extracted data")
        processed = campaign._process_packet(original)
        
        self.assertIsNotNone(processed)
        self.assertIsInstance(processed, Raw)
        if processed:  # Type guard
            self.assertEqual(bytes(processed), b"extracted data")
    
    def test_process_packet_with_repackaging(self):
        """Test packet processing with repackaging."""
        campaign = PcapFuzzCampaign()
        campaign.extract_layer = "UDP"
        campaign.repackage_in = "IP/UDP"
        campaign.target = "10.0.0.1"
        
        original = IP()/UDP()/Raw(b"test")
        processed = campaign._process_packet(original)
        
        self.assertIsNotNone(processed)
        if processed:  # Type guard
            self.assertTrue(processed.haslayer(IP))
            self.assertTrue(processed.haslayer(UDP))
            self.assertEqual(processed[IP].dst, "10.0.0.1")
    
    def test_process_packet_extraction_fails(self):
        """Test packet processing when extraction fails."""
        campaign = PcapFuzzCampaign()
        campaign.extract_layer = "TCP"  # Not present in UDP packet
        
        original = IP()/UDP()/Raw(b"data")
        processed = campaign._process_packet(original)
        
        self.assertIsNone(processed)
    
    @patch('pcapfuzz.rdpcap')
    def test_get_packet_with_embedded_config(self, mock_rdpcap):
        """Test getting packet from PCAP files."""
        campaign = PcapFuzzCampaign()
        campaign.pcap_folder = self.temp_dir
        
        # Mock rdpcap to return test packets
        mock_rdpcap.return_value = [IP()/UDP()/Raw(b"test")]
        
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', return_value=['test.pcap']):
                packet = campaign.get_packet_with_embedded_config()
        
        self.assertIsNotNone(packet)
    
    def test_get_packet_no_pcap_folder(self):
        """Test getting packet when PCAP folder doesn't exist."""
        campaign = PcapFuzzCampaign()
        campaign.pcap_folder = "/nonexistent"
        
        packet = campaign.get_packet_with_embedded_config()
        # Now returns a dummy packet for validation instead of None
        self.assertIsNotNone(packet)
        assert packet is not None
        if packet is not None:
            self.assertTrue(packet.haslayer(IP))
            self.assertTrue(packet.haslayer(TCP))
        
    def test_fuzz_mode_validation(self):
        """Test that fuzz_mode accepts valid values."""
        campaign = PcapFuzzCampaign()
        
        valid_modes = ["field", "binary", "both", "none"]
        for mode in valid_modes:
            campaign.fuzz_mode = mode
            self.assertEqual(campaign.fuzz_mode, mode)


class TestPcapFuzzStandalone(unittest.TestCase):
    """Test cases for standalone pcap_fuzz function."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)
    
    @patch('pcapfuzz.PcapFuzzCampaign')
    def test_pcap_fuzz_basic(self, mock_campaign_class):
        """Test basic pcap_fuzz function usage."""
        mock_campaign = MagicMock()
        mock_campaign.execute.return_value = True
        mock_campaign_class.return_value = mock_campaign
        
        result = pcap_fuzz(self.temp_dir, extract_layer="UDP")
        
        # Verify campaign was configured correctly
        mock_campaign_class.assert_called_once()
        self.assertEqual(mock_campaign.pcap_folder, self.temp_dir)
        self.assertEqual(mock_campaign.extract_layer, "UDP")
        mock_campaign.execute.assert_called_once()
        self.assertTrue(result)
    
    @patch('pcapfuzz.PcapFuzzCampaign')
    def test_pcap_fuzz_with_kwargs(self, mock_campaign_class):
        """Test pcap_fuzz function with additional arguments."""
        mock_campaign = MagicMock()
        mock_campaign.execute.return_value = True
        mock_campaign_class.return_value = mock_campaign
        
        result = pcap_fuzz(
            self.temp_dir,
            extract_layer="TCP",
            fuzz_mode="binary",
            target="10.0.0.1",
            iterations=50
        )
        
        # Verify all attributes were set
        self.assertEqual(mock_campaign.pcap_folder, self.temp_dir)
        self.assertEqual(mock_campaign.extract_layer, "TCP")
        self.assertEqual(mock_campaign.fuzz_mode, "binary")
        self.assertEqual(mock_campaign.target, "10.0.0.1")
        self.assertEqual(mock_campaign.iterations, 50)
        mock_campaign.execute.assert_called_once()


class TestPcapFuzzIntegration(unittest.TestCase):
    """Integration tests for PCAP fuzzing with real files."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.pcap_file = os.path.join(self.temp_dir, "integration_test.pcap")
        
        # Create realistic test packets
        self.test_packets = [
            # DNS query
            IP(src="192.168.1.10", dst="10.10.10.10")/UDP(sport=12345, dport=53)/Raw(b"\\x12\\x34\\x01\\x00\\x00\\x01test"),
            # HTTP request  
            IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=45678, dport=80)/Raw(b"GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"),
            # Custom UDP protocol
            IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=8888, dport=9999)/Raw(b"CUSTOM_PROTO_DATA_HERE"),
        ]
        
        wrpcap(self.pcap_file, self.test_packets)
    
    def tearDown(self):
        """Clean up integration test environment."""
        shutil.rmtree(self.temp_dir)
    
    def test_integration_basic_regression(self):
        """Test basic regression testing integration."""
        campaign = PcapFuzzCampaign()
        campaign.pcap_folder = self.temp_dir
        campaign.fuzz_mode = "none"  # No fuzzing
        campaign.output_network = False  # Don't send packets
        campaign.verbose = False  # Reduce output during tests
        
        # Test that campaign validates and can get packets
        packet = campaign.get_packet_with_embedded_config()
        self.assertIsNotNone(packet)
        
        # Test that validation passes
        self.assertTrue(campaign.validate_campaign())
    
    def test_integration_udp_extraction(self):
        """Test UDP payload extraction integration."""
        campaign = PcapFuzzCampaign()
        campaign.pcap_folder = self.temp_dir
        campaign.extract_layer = "UDP"
        campaign.repackage_in = "IP/UDP"
        campaign.fuzz_mode = "none"
        campaign.output_network = False
        campaign.verbose = False
        
        # Process the first UDP packet
        udp_packet = next(p for p in self.test_packets if p.haslayer(UDP))
        processed = campaign._process_packet(udp_packet)
        
        self.assertIsNotNone(processed)
        if processed:  # Type guard
            self.assertTrue(processed.haslayer(IP))
            self.assertTrue(processed.haslayer(UDP))
    
    def test_integration_tcp_extraction(self):
        """Test TCP payload extraction integration."""
        campaign = PcapFuzzCampaign()
        campaign.pcap_folder = self.temp_dir
        campaign.extract_layer = "TCP"
        campaign.repackage_in = "IP/TCP"
        campaign.fuzz_mode = "none"
        campaign.output_network = False
        campaign.verbose = False
        
        # Process the first TCP packet
        tcp_packet = next(p for p in self.test_packets if p.haslayer(TCP))
        processed = campaign._process_packet(tcp_packet)
        
        self.assertIsNotNone(processed)
        if processed:  # Type guard
            self.assertTrue(processed.haslayer(IP))
            self.assertTrue(processed.haslayer(TCP))


if __name__ == '__main__':
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPcapFuzzCampaign))
    suite.addTests(loader.loadTestsFromTestCase(TestPcapFuzzStandalone))
    suite.addTests(loader.loadTestsFromTestCase(TestPcapFuzzIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)
