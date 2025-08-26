#!/usr/bin/env python3
"""
Tests for packet processing utilities

This module tests the packet processing utility functions and classes in
packetfuzz.utils.packet_processing.
"""

import unittest
import sys
import os
from typing import Optional

# Third-party imports  
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP
from scapy.packet import Packet, Raw

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.utils.packet_processing import (
    PacketProcessingConfig,
    extract_layers,
    filter_include_layers, 
    filter_exclude_layers,
    repackage_payload,
    convert_to_scapy,
    process_packet,
    create_layer_extraction_config,
    create_layer_filter_config
)
from conftest import cleanup_test_files


class TestPacketProcessingConfig(unittest.TestCase):
    """Test cases for PacketProcessingConfig dataclass."""
    
    def test_config_defaults(self):
        """Test that config initializes with proper defaults."""
        config = PacketProcessingConfig()
        
        self.assertIsNone(config.extract_at_layer)
        self.assertIsNone(config.include_layers)
        self.assertIsNone(config.exclude_layers)
        self.assertIsNone(config.repackage_template)
    
    def test_config_initialization(self):
        """Test config initialization with values."""
        template = IP(dst="192.168.1.1") / UDP(dport=53)
        config = PacketProcessingConfig(
            extract_at_layer="UDP",
            include_layers=["IP", "UDP", "DNS"],
            exclude_layers=["Raw"],
            repackage_template=template
        )
        
        self.assertEqual(config.extract_at_layer, "UDP")
        self.assertEqual(config.include_layers, ["IP", "UDP", "DNS"])
        self.assertEqual(config.exclude_layers, ["Raw"])
        self.assertEqual(config.repackage_template, template)


class TestExtractLayers(unittest.TestCase):
    """Test cases for extract_layers function."""
    
    def setUp(self):
        """Set up test packets."""
        cleanup_test_files()
        
        # Create test packets with different layer structures
        self.udp_packet = IP(dst="192.168.1.1") / UDP(dport=53) / Raw(b"dns query")
        self.tcp_packet = IP(dst="192.168.1.2") / TCP(dport=80) / Raw(b"http data")
        self.eth_packet = Ether(dst="aa:bb:cc:dd:ee:ff") / IP(dst="10.0.0.1") / UDP(dport=1234) / Raw(b"custom data")
        self.dns_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
        self.nested_packet = Ether() / IP() / TCP() / HTTP() / Raw(b"web data")
    
    def tearDown(self):
        """Clean up after tests."""
        cleanup_test_files()
    
    def test_extract_udp_layer(self):
        """Test extracting at UDP layer."""
        result = extract_layers(self.udp_packet, extract_at_layer="UDP")
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, Raw)
        if result:  # Type guard
            self.assertEqual(bytes(result), b"dns query")
    
    def test_extract_tcp_layer(self):
        """Test extracting at TCP layer."""
        result = extract_layers(self.tcp_packet, extract_at_layer="TCP")
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, Raw)
        if result:  # Type guard
            self.assertEqual(bytes(result), b"http data")
    
    def test_extract_ip_layer(self):
        """Test extracting at IP layer."""
        result = extract_layers(self.eth_packet, extract_at_layer="IP")
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(UDP))
            self.assertTrue(result.haslayer(Raw))
            self.assertEqual(bytes(result[Raw]), b"custom data")
    
    def test_extract_ethernet_layer(self):
        """Test extracting at Ethernet layer."""
        result = extract_layers(self.eth_packet, extract_at_layer="Ethernet")
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertTrue(result.haslayer(Raw))
    
    def test_extract_nonexistent_layer(self):
        """Test extracting layer that doesn't exist."""
        result = extract_layers(self.udp_packet, extract_at_layer="TCP")
        
        self.assertIsNone(result)
    
    def test_extract_with_include_layers(self):
        """Test extraction with layer inclusion filter."""
        result = extract_layers(self.dns_packet, include_layers=["IP", "UDP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
    
    def test_extract_with_exclude_layers(self):
        """Test extraction with layer exclusion filter."""
        result = extract_layers(self.udp_packet, exclude_layers=["Raw"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(Raw))
    
    def test_extract_none_packet(self):
        """Test extraction with None packet."""
        result = extract_layers(None, extract_at_layer="UDP")
        
        self.assertIsNone(result)
    
    def test_extract_no_operations(self):
        """Test extraction with no operations specified."""
        result = extract_layers(self.udp_packet)
        
        self.assertEqual(result, self.udp_packet)


class TestFilterIncludeLayers(unittest.TestCase):
    """Test cases for filter_include_layers function."""
    
    def setUp(self):
        """Set up test packets."""
        self.complex_packet = IP(dst="192.168.1.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="test.com")) / Raw(b"extra")
        self.simple_packet = IP(dst="192.168.1.2") / UDP(dport=80) / Raw(b"data")
    
    def test_include_single_layer(self):
        """Test including a single layer type."""
        result = filter_include_layers(self.simple_packet, ["IP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertFalse(result.haslayer(UDP))
            self.assertFalse(result.haslayer(Raw))
    
    def test_include_multiple_layers(self):
        """Test including multiple layer types."""
        result = filter_include_layers(self.complex_packet, ["IP", "UDP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
            self.assertFalse(result.haslayer(Raw))
    
    def test_include_nonexistent_layer(self):
        """Test including a layer that doesn't exist in packet."""
        result = filter_include_layers(self.simple_packet, ["TCP"])
        
        self.assertIsNone(result)
    
    def test_include_empty_list(self):
        """Test including with empty list."""
        result = filter_include_layers(self.simple_packet, [])
        
        self.assertIsNone(result)
    
    def test_include_none_packet(self):
        """Test including with None packet."""
        result = filter_include_layers(None, ["IP"])
        
        self.assertIsNone(result)
    
    def test_include_preserves_field_values(self):
        """Test that inclusion preserves field values."""
        test_packet = IP(dst="192.168.1.100", ttl=64) / UDP(dport=12345) / Raw(b"test")
        result = filter_include_layers(test_packet, ["IP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertEqual(result[IP].dst, "192.168.1.100")
            self.assertEqual(result[IP].ttl, 64)


class TestFilterExcludeLayers(unittest.TestCase):
    """Test cases for filter_exclude_layers function."""
    
    def setUp(self):
        """Set up test packets."""
        self.complex_packet = IP(dst="192.168.1.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="test.com")) / Raw(b"extra")
        self.simple_packet = IP(dst="192.168.1.2") / UDP(dport=80) / Raw(b"data")
    
    def test_exclude_single_layer(self):
        """Test excluding a single layer type."""
        result = filter_exclude_layers(self.simple_packet, ["Raw"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(Raw))
    
    def test_exclude_multiple_layers(self):
        """Test excluding multiple layer types."""
        result = filter_exclude_layers(self.complex_packet, ["DNS", "Raw"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
            self.assertFalse(result.haslayer(Raw))
    
    def test_exclude_first_layer(self):
        """Test excluding the first layer in chain."""
        result = filter_exclude_layers(self.simple_packet, ["IP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertFalse(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertTrue(result.haslayer(Raw))
    
    def test_exclude_all_layers(self):
        """Test excluding all layers."""
        result = filter_exclude_layers(self.simple_packet, ["IP", "UDP", "Raw"])
        
        self.assertIsNone(result)
    
    def test_exclude_nonexistent_layer(self):
        """Test excluding a layer that doesn't exist."""
        result = filter_exclude_layers(self.simple_packet, ["TCP"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertEqual(result[IP].dst, self.simple_packet[IP].dst)
            self.assertTrue(result.haslayer(UDP))
            self.assertTrue(result.haslayer(Raw))
    
    def test_exclude_empty_list(self):
        """Test excluding with empty list."""
        result = filter_exclude_layers(self.simple_packet, [])
        
        self.assertEqual(result, self.simple_packet)
    
    def test_exclude_none_packet(self):
        """Test excluding with None packet."""
        result = filter_exclude_layers(None, ["IP"])
        
        self.assertIsNone(result)
    
    def test_exclude_preserves_field_values(self):
        """Test that exclusion preserves field values."""
        test_packet = IP(dst="192.168.1.100", ttl=64) / UDP(dport=12345) / Raw(b"test")
        result = filter_exclude_layers(test_packet, ["Raw"])
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertEqual(result[IP].dst, "192.168.1.100")
            self.assertEqual(result[IP].ttl, 64)
            self.assertEqual(result[UDP].dport, 12345)


class TestRepackagePayload(unittest.TestCase):
    """Test cases for repackage_payload function."""
    
    def setUp(self):
        """Set up test data."""
        self.payload = Raw(b"test payload data")
        self.ip_udp_template = IP(dst="192.168.1.100") / UDP(dport=53)
        self.ip_tcp_template = IP(dst="10.0.0.1") / TCP(dport=80)
        self.ip_only_template = IP(dst="172.16.0.1")
    
    def test_repackage_with_ip_udp(self):
        """Test repackaging with IP/UDP template."""
        result = repackage_payload(self.payload, self.ip_udp_template)
        
        self.assertTrue(result.haslayer(IP))
        self.assertTrue(result.haslayer(UDP))
        self.assertTrue(result.haslayer(Raw))
        self.assertEqual(result[IP].dst, "192.168.1.100")
        self.assertEqual(result[UDP].dport, 53)
        self.assertEqual(bytes(result[Raw]), b"test payload data")
    
    def test_repackage_with_ip_tcp(self):
        """Test repackaging with IP/TCP template."""
        result = repackage_payload(self.payload, self.ip_tcp_template)
        
        self.assertTrue(result.haslayer(IP))
        self.assertTrue(result.haslayer(TCP))
        self.assertTrue(result.haslayer(Raw))
        self.assertEqual(result[IP].dst, "10.0.0.1")
        self.assertEqual(result[TCP].dport, 80)
        self.assertEqual(bytes(result[Raw]), b"test payload data")
    
    def test_repackage_with_ip_only(self):
        """Test repackaging with IP-only template."""
        result = repackage_payload(self.payload, self.ip_only_template)
        
        self.assertTrue(result.haslayer(IP))
        self.assertTrue(result.haslayer(Raw))
        self.assertEqual(result[IP].dst, "172.16.0.1")
        self.assertEqual(bytes(result[Raw]), b"test payload data")
    
    def test_repackage_with_none_template(self):
        """Test repackaging with None template."""
        result = repackage_payload(self.payload, None)
        
        self.assertEqual(result, self.payload)
    
    def test_repackage_complex_payload(self):
        """Test repackaging with complex payload."""
        complex_payload = UDP(dport=123) / Raw(b"ntp data")
        template = IP(dst="192.168.1.50")
        result = repackage_payload(complex_payload, template)
        
        self.assertTrue(result.haslayer(IP))
        self.assertTrue(result.haslayer(UDP))
        self.assertTrue(result.haslayer(Raw))
        self.assertEqual(result[IP].dst, "192.168.1.50")
        self.assertEqual(result[UDP].dport, 123)
        self.assertEqual(bytes(result[Raw]), b"ntp data")
    
    def test_repackage_preserves_template_fields(self):
        """Test that repackaging preserves template field values."""
        template = IP(dst="192.168.1.200", ttl=32) / UDP(dport=443, sport=12345)
        result = repackage_payload(self.payload, template)
        
        self.assertEqual(result[IP].dst, "192.168.1.200")
        self.assertEqual(result[IP].ttl, 32)
        self.assertEqual(result[UDP].dport, 443)
        self.assertEqual(result[UDP].sport, 12345)


class TestConvertToScapy(unittest.TestCase):
    """Test cases for convert_to_scapy function."""
    
    def setUp(self):
        """Set up test data."""
        self.ip_packet = IP(dst="192.168.1.1") / UDP(dport=53) / Raw(b"dns")
        self.eth_packet = Ether(dst="aa:bb:cc:dd:ee:ff") / IP(dst="10.0.0.1") / TCP(dport=80)
        self.ip_bytes = bytes(self.ip_packet)
        self.eth_bytes = bytes(self.eth_packet)
        self.invalid_bytes = b"not a valid packet"
    
    def test_convert_ip_bytes(self):
        """Test converting IP packet bytes."""
        result = convert_to_scapy(self.ip_bytes)
        
        self.assertIsInstance(result, IP)
        self.assertTrue(result.haslayer(UDP))
        # Note: Raw layer may not be present after reconstruction
    
    def test_convert_ethernet_bytes(self):
        """Test converting Ethernet packet bytes."""
        result = convert_to_scapy(self.eth_bytes)
        
        self.assertIsInstance(result, Ether)
        self.assertTrue(result.haslayer(IP))
        self.assertTrue(result.haslayer(TCP))
    
    def test_convert_with_ip_hint(self):
        """Test converting with IP protocol hint."""
        result = convert_to_scapy(self.ip_bytes, protocol_hint="IP")
        
        self.assertIsInstance(result, IP)
        self.assertTrue(result.haslayer(UDP))
    
    def test_convert_with_ether_hint(self):
        """Test converting with Ethernet protocol hint."""
        result = convert_to_scapy(self.eth_bytes, protocol_hint="Ether")
        
        self.assertIsInstance(result, Ether)
        self.assertTrue(result.haslayer(IP))
    
    def test_convert_invalid_data(self):
        """Test converting invalid packet data."""
        result = convert_to_scapy(self.invalid_bytes)
        
        # Auto-detection may parse as Ethernet or Raw depending on content
        self.assertIsInstance(result, (Raw, Ether))
        # Ensure our data is preserved somewhere in the result
        self.assertIn(b"valid", bytes(result))
    
    def test_convert_empty_data(self):
        """Test converting empty data."""
        result = convert_to_scapy(b"")
        
        self.assertIsInstance(result, Raw)
        self.assertEqual(bytes(result), b"")
    
    def test_convert_prefers_multilayer(self):
        """Test that converter prefers parsers that create multiple layers."""
        # This should prefer Ether parser over IP for ethernet frames
        result = convert_to_scapy(self.eth_bytes)
        
        # Should parse as Ethernet with multiple layers
        self.assertTrue(len(result.layers()) > 1)


class TestProcessPacket(unittest.TestCase):
    """Test cases for process_packet function."""
    
    def setUp(self):
        """Set up test data."""
        self.test_packet = IP(dst="192.168.1.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="test.com")) / Raw(b"extra")
        self.simple_packet = IP(dst="192.168.1.2") / TCP(dport=80) / Raw(b"http data")
    
    def test_process_no_config(self):
        """Test processing with no configuration."""
        result = process_packet(self.test_packet, None)
        
        self.assertEqual(result, self.test_packet)
    
    def test_process_empty_config(self):
        """Test processing with empty configuration."""
        config = PacketProcessingConfig()
        result = process_packet(self.test_packet, config)
        
        self.assertEqual(result, self.test_packet)
    
    def test_process_with_extraction(self):
        """Test processing with layer extraction."""
        config = PacketProcessingConfig(extract_at_layer="UDP")
        result = process_packet(self.test_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(DNS))
            self.assertTrue(result.haslayer(Raw))
            self.assertFalse(result.haslayer(IP))
            self.assertFalse(result.haslayer(UDP))
    
    def test_process_with_repackaging(self):
        """Test processing with repackaging."""
        template = IP(dst="10.0.0.1") / UDP(dport=1234)
        config = PacketProcessingConfig(
            extract_at_layer="UDP",
            repackage_template=template
        )
        result = process_packet(self.test_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertEqual(result[IP].dst, "10.0.0.1")
            self.assertEqual(result[UDP].dport, 1234)
    
    def test_process_with_include_filter(self):
        """Test processing with include filter."""
        config = PacketProcessingConfig(include_layers=["IP", "UDP"])
        result = process_packet(self.test_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
            self.assertFalse(result.haslayer(Raw))
    
    def test_process_with_exclude_filter(self):
        """Test processing with exclude filter."""
        config = PacketProcessingConfig(exclude_layers=["DNS", "Raw"])
        result = process_packet(self.test_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
            self.assertFalse(result.haslayer(Raw))
    
    def test_process_extraction_failure(self):
        """Test processing when extraction fails."""
        config = PacketProcessingConfig(extract_at_layer="ICMP")
        result = process_packet(self.test_packet, config)
        
        self.assertIsNone(result)
    
    def test_process_none_packet(self):
        """Test processing None packet."""
        config = PacketProcessingConfig(extract_at_layer="UDP")
        result = process_packet(None, config)
        
        self.assertIsNone(result)
    
    def test_process_bytes_input(self):
        """Test processing with bytes input."""
        packet_bytes = bytes(self.simple_packet)
        config = PacketProcessingConfig()
        result = process_packet(packet_bytes, config)
        
        # Should convert bytes to packet
        self.assertIsInstance(result, (IP, Raw))


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility configuration functions."""
    
    def test_create_layer_extraction_config(self):
        """Test creating layer extraction configuration."""
        template = IP(dst="192.168.1.1") / UDP(dport=53)
        config = create_layer_extraction_config("UDP", template)
        
        self.assertEqual(config.extract_at_layer, "UDP")
        self.assertEqual(config.repackage_template, template)
        self.assertIsNone(config.include_layers)
        self.assertIsNone(config.exclude_layers)
    
    def test_create_layer_extraction_config_no_template(self):
        """Test creating layer extraction config without template."""
        config = create_layer_extraction_config("TCP")
        
        self.assertEqual(config.extract_at_layer, "TCP")
        self.assertIsNone(config.repackage_template)
    
    def test_create_layer_filter_config_include(self):
        """Test creating layer filter config with include."""
        config = create_layer_filter_config(include=["IP", "UDP", "DNS"])
        
        self.assertEqual(config.include_layers, ["IP", "UDP", "DNS"])
        self.assertIsNone(config.exclude_layers)
        self.assertIsNone(config.extract_at_layer)
    
    def test_create_layer_filter_config_exclude(self):
        """Test creating layer filter config with exclude."""
        config = create_layer_filter_config(exclude=["Raw", "Padding"])
        
        self.assertEqual(config.exclude_layers, ["Raw", "Padding"])
        self.assertIsNone(config.include_layers)
        self.assertIsNone(config.extract_at_layer)
    
    def test_create_layer_filter_config_empty(self):
        """Test creating empty layer filter config."""
        config = create_layer_filter_config()
        
        self.assertIsNone(config.include_layers)
        self.assertIsNone(config.exclude_layers)
        self.assertIsNone(config.extract_at_layer)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for complex packet processing scenarios."""
    
    def setUp(self):
        """Set up complex test scenarios."""
        # Web traffic scenario
        self.web_packet = (Ether(dst="aa:bb:cc:dd:ee:ff") / 
                          IP(src="192.168.1.10", dst="93.184.216.34") / 
                          TCP(sport=45678, dport=80) / 
                          Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        
        # DNS scenario
        self.dns_packet = (IP(src="192.168.1.10", dst="8.8.8.8") / 
                          UDP(sport=12345, dport=53) / 
                          DNS(qd=DNSQR(qname="example.com", qtype="A")))
        
        # Custom protocol scenario
        self.custom_packet = (Ether() / 
                             IP(dst="10.0.0.1") / 
                             UDP(dport=9999) / 
                             Raw(b"CUSTOM_PROTOCOL_HEADER") / 
                             Raw(b"payload_data"))
    
    def test_web_traffic_payload_extraction(self):
        """Test extracting HTTP payload from web traffic."""
        config = PacketProcessingConfig(
            extract_at_layer="TCP",
            repackage_template=IP(dst="192.168.1.100") / TCP(dport=8080)
        )
        
        result = process_packet(self.web_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(TCP))
            self.assertTrue(result.haslayer(Raw))
            self.assertEqual(result[IP].dst, "192.168.1.100")
            self.assertEqual(result[TCP].dport, 8080)
            self.assertIn(b"GET /index.html", bytes(result[Raw]))
    
    def test_dns_query_filtering(self):
        """Test filtering DNS packets to keep only core layers."""
        config = PacketProcessingConfig(include_layers=["IP", "UDP"])
        
        result = process_packet(self.dns_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(DNS))
            self.assertEqual(result[IP].dst, "8.8.8.8")
            self.assertEqual(result[UDP].dport, 53)
    
    def test_custom_protocol_layer_stripping(self):
        """Test stripping Ethernet layer from custom protocol."""
        config = PacketProcessingConfig(
            extract_at_layer="Ethernet",
            exclude_layers=["Raw"]
        )
        
        result = process_packet(self.custom_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertFalse(result.haslayer(Ether))
            self.assertFalse(result.haslayer(Raw))
    
    def test_complex_pipeline_extraction_and_repackaging(self):
        """Test complex pipeline with extraction and repackaging."""
        # Extract UDP payload and repackage with new headers
        # Note: We don't exclude DNS since that's what we extracted at UDP level
        config = PacketProcessingConfig(
            extract_at_layer="UDP",
            repackage_template=Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="172.16.0.1") / UDP(dport=1337)
        )
        
        result = process_packet(self.dns_packet, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(Ether))
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(UDP))
            self.assertTrue(result.haslayer(DNS))  # DNS should be preserved as extracted payload
            self.assertEqual(result[Ether].dst, "ff:ff:ff:ff:ff:ff")
            self.assertEqual(result[IP].dst, "172.16.0.1")
            self.assertEqual(result[UDP].dport, 1337)
    
    def test_error_recovery_invalid_extraction(self):
        """Test error recovery when extraction fails."""
        config = PacketProcessingConfig(
            extract_at_layer="NONEXISTENT",
            repackage_template=IP() / UDP()
        )
        
        result = process_packet(self.web_packet, config)
        
        # Should return None when extraction fails
        self.assertIsNone(result)
    
    def test_edge_case_single_layer_packet(self):
        """Test processing packet with single layer."""
        single_layer = Raw(b"raw data only")
        config = PacketProcessingConfig(
            include_layers=["Raw"],
            repackage_template=IP(dst="192.168.1.1")
        )
        
        result = process_packet(single_layer, config)
        
        self.assertIsNotNone(result)
        if result:  # Type guard
            self.assertTrue(result.haslayer(IP))
            self.assertTrue(result.haslayer(Raw))
            self.assertEqual(bytes(result[Raw]), b"raw data only")


if __name__ == '__main__':
    unittest.main()
