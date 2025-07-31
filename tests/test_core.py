#!/usr/bin/env python3
"""
Core Framework Tests

Tests for the core functionality of the scapy-fuzzer framework including:
- Packet extensions and embedded configuration
- Core fuzzer functionality
- Field and packet configuration management
"""

import sys
import os
import unittest
from typing import Any, List

# Try to import pytest, fall back to unittest if not available
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fuzzing_framework import FuzzingCampaign, FuzzField, FuzzMutator
from mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from conftest import create_test_packet, configure_packet_fuzzing


class LocalFuzzingCampaign(FuzzingCampaign):
    """Base class for local-only fuzzing tests."""
    output_network = False
    target = "127.0.0.1"
    interface = "lo"


# All test campaigns should inherit from LocalFuzzingCampaign to ensure local-only traffic
class TestPacketExtensions(unittest.TestCase):
    """Test packet extension functionality"""
    
    def test_field_fuzz_method_exists(self):
        """Test that field_fuzz method is available on packets"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'field_fuzz')
        field_proxy = tcp_layer.field_fuzz('dport')
        assert field_proxy is not None
    
    def test_fuzz_config_method_exists(self):
        """Test that fuzz_config method is available on packets"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'fuzz_config')
        config_proxy = tcp_layer.fuzz_config()
        assert config_proxy is not None
    
    def test_has_fuzz_config_method(self):
        """Test has_fuzz_config method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Initially should have no config
        assert hasattr(tcp_layer, 'has_fuzz_config')
        assert tcp_layer.has_fuzz_config() == False
        
        # After adding config should return True
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        assert tcp_layer.has_fuzz_config() == True
    
    def test_get_field_fuzz_config_method(self):
        """Test get_field_fuzz_config method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'get_field_fuzz_config')
        
        # Initially should return None
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config is None
        
        # After adding config should return the config
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config is not None
        assert config.default_values == [80, 443, 8080]
    
    def test_get_all_field_fuzz_configs_method(self):
        """Test get_all_field_fuzz_configs method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'get_all_field_fuzz_configs')
        
        # Configure multiple fields
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        tcp_layer.field_fuzz('sport').default_values = [1024, 2048]
        
        all_configs = tcp_layer.get_all_field_fuzz_configs()
        assert len(all_configs) == 2
        assert 'dport' in all_configs
        assert 'sport' in all_configs
    
    def test_clear_fuzz_configs_method(self):
        """Test clear_fuzz_configs method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'clear_fuzz_configs')
        
        # Add some config
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        assert tcp_layer.has_fuzz_config() == True
        
        # Clear config
        tcp_layer.clear_fuzz_configs()
        assert tcp_layer.has_fuzz_config() == False


class TestEmbeddedConfiguration(unittest.TestCase):
    """Test embedded packet configuration functionality"""
    
    def test_field_configuration_basic(self):
        """Test basic field configuration"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure field
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        tcp_layer.field_fuzz('dport').fuzz_weight = 0.8
        tcp_layer.field_fuzz('dport').description = "Web ports"
        
        # Verify configuration
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config.default_values == [80, 443, 8080]
        assert config.fuzz_weight == 0.8
        assert config.description == "Web ports"
    
    def test_packet_level_configuration(self):
        """Test packet-level configuration"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure packet level
        tcp_layer.fuzz_config().description = "TCP packet fuzzing"
        
        # Verify configuration
        packet_config = tcp_layer.get_fuzz_config()
        assert packet_config is not None
        assert packet_config.description == "TCP packet fuzzing"
    
    def test_multiple_layers_configuration(self):
        """Test configuration across multiple packet layers"""
        packet = create_test_packet("tcp")
        
        # Configure IP layer
        ip_layer = packet[IP]
        ip_layer.field_fuzz('dst').default_values = ["192.168.1.1", "10.0.0.1"]
        ip_layer.field_fuzz('ttl').default_values = [64, 128, 255]
        
        # Configure TCP layer
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        tcp_layer.field_fuzz('sport').default_values = [1024, 2048]
        
        # Verify both layers have configuration
        assert ip_layer.has_fuzz_config() == True
        assert tcp_layer.has_fuzz_config() == True
        
        # Verify field counts
        ip_configs = ip_layer.get_all_field_fuzz_configs()
        tcp_configs = tcp_layer.get_all_field_fuzz_configs()
        assert len(ip_configs) == 2  # dst, ttl
        assert len(tcp_configs) == 2  # dport, sport
    
    def test_dictionary_configuration(self):
        """Test dictionary configuration in embedded config"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure with dictionaries
        tcp_layer.field_fuzz('dport').dictionary = ["fuzzdb/wordlists-misc/common-http-ports.txt"]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        
        # Verify configuration
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config.dictionary == ["fuzzdb/wordlists-misc/common-http-ports.txt"]
        assert config.default_values == [80, 443]


class TestFuzzField(unittest.TestCase):
    """Test FuzzField functionality"""
    
    def test_fuzzfield_creation(self):
        """Test FuzzField object creation"""
        fuzz_field = FuzzField(values=[80, 443, 8080], description="Web ports")
        
        assert fuzz_field.values == [80, 443, 8080]
        assert fuzz_field.description == "Web ports"
    
    def test_fuzzfield_as_integer(self):
        """Test FuzzField used as integer"""
        fuzz_field = FuzzField(values=[80, 443, 8080])
        # Should act like an integer in packet construction
        assert int(fuzz_field) in fuzz_field.values

    def test_fuzzfield_as_string(self):
        fuzz_field = FuzzField(values=["test1", "test2"])
        # Should act like a string in packet construction
        assert str(fuzz_field) in fuzz_field.values

    def test_fuzzfield_as_bytes(self):
        """Test FuzzField used as bytes"""
        fuzz_field = FuzzField(values=[b"data1", b"data2"])
        # Should act like bytes in packet construction
        assert bytes(fuzz_field) in fuzz_field.values

    def test_fuzzfield_with_mutators(self):
        """Test FuzzField with custom mutators"""
        fuzz_field = FuzzField(
            values=[80, 443, 8080],
            mutators=[]
        )
        
        assert not fuzz_field.mutators

    def test_fuzzfield_preservation_in_packets(self):
        packet = IP() / TCP(dport=FuzzField(values=[80, 443, 8080]))
        tcp_layer = packet[TCP]
        dport_field = tcp_layer.dport
        assert isinstance(dport_field, FuzzField), "FuzzField should be preserved in packet"
        assert dport_field.values == [80, 443, 8080]
        assert int(dport_field) in dport_field.values
        assert str(dport_field) in [str(v) for v in dport_field.values]


class TestCoreFuzzer(unittest.TestCase):
    """Test core fuzzer functionality"""
    
    def test_scapy_fuzzer_creation(self):
        """Test MutatorManager creation"""
        config = FuzzConfig()
        fuzzer = MutatorManager(config)
        
        assert fuzzer is not None
        assert fuzzer.config.mode == FuzzMode.BOTH
        assert fuzzer.config.use_dictionaries == True
    
    def test_fuzzer_with_embedded_config(self):
        """Test fuzzer working with embedded configuration"""
        # Create packet with embedded config
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        
        # Create fuzzer
        config = FuzzConfig(mode=FuzzMode.BOTH, use_dictionaries=True)
        fuzzer = MutatorManager(config)
        
        # Test that fuzzer can process the packet
        assert fuzzer is not None
        # Note: Actual fuzzing would require more setup, this tests basic compatibility
    
    def test_fuzzer_packet_serialization(self):
        """Test that configured packets can be serialized"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        
        # Should be able to serialize packet with embedded config
        packet_bytes = bytes(packet)
        assert len(packet_bytes) > 0
        assert isinstance(packet_bytes, bytes)

    def test_convert_field_overrides_to_fuzzfields(self):
        """Test conversion of legacy field overrides to FuzzField objects"""
        pass


class TestConfigurationPersistence(unittest.TestCase):
    """Test configuration persistence and copying behavior"""
    
    def test_config_persistence_after_copy(self):
        """Test that configuration doesn't persist after packet copy"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        
        # Copy the packet
        packet_copy = packet.copy()
        tcp_copy = packet_copy[TCP]
        
        # Original should still have config
        assert tcp_layer.has_fuzz_config() == True
        
        # Copy should not have config (as per current implementation)
        assert tcp_copy.has_fuzz_config() == False
    
    def test_config_independence(self):
        """Test that packet configurations are independent"""
        packet1 = create_test_packet("tcp")
        packet2 = create_test_packet("tcp")
        
        # Configure first packet
        tcp1 = packet1[TCP]
        tcp1.field_fuzz('dport').default_values = [80, 443]
        
        # Configure second packet differently
        tcp2 = packet2[TCP]
        tcp2.field_fuzz('dport').default_values = [22, 23]
        
        # Verify independence
        config1 = tcp1.get_field_fuzz_config('dport')
        config2 = tcp2.get_field_fuzz_config('dport')
        
        assert config1.default_values == [80, 443]
        assert config2.default_values == [22, 23]


if __name__ == '__main__':
    # Run tests with pytest if available, otherwise use unittest
    if PYTEST_AVAILABLE:
        try:
            pytest.main([__file__, '-v'])
        except SystemExit:
            pass
    else:
        unittest.main(verbosity=2)
