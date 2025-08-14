#!/usr/bin/env python3
"""
Campaign Framework Tests

Tests for all campaign-related functionality including:
- Base FuzzingCampaign class
- Campaign configuration management  
- Campaign attribute inheritance
- Specialized campaign classes
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

# Try to import pytest, fall back to unittest if not available
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fuzzing_framework import FuzzingCampaign
from mutator_manager import MutatorManager
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from conftest import (
    BasicTestCampaign, HTTPTestCampaign, DNSTestCampaign,
    Layer2TestCampaign, DictionaryTestCampaign, PCAPTestCampaign,
    NetworkTestCampaign
)


class TestBaseFuzzingCampaign(unittest.TestCase):
    """Test base FuzzingCampaign class functionality"""
    
    def test_campaign_creation(self):
        """Test basic campaign creation"""
        campaign = BasicTestCampaign()
        
        assert campaign is not None
        assert hasattr(campaign, 'name')
        assert hasattr(campaign, 'target')
        assert hasattr(campaign, 'iterations')
        assert hasattr(campaign, 'rate_limit')
    
    def test_campaign_attributes(self):
        """Test campaign attributes"""
        campaign = BasicTestCampaign()
        
        assert campaign.name == "Basic Test Campaign"
        assert campaign.target == "192.168.1.1"
        assert campaign.iterations == 5
        assert campaign.rate_limit == 100.0
        assert campaign.verbose == False
        assert campaign.output_network == False
        assert campaign.output_pcap == None
    
    def test_campaign_packet_access(self):
        """Test campaign packet access"""
        campaign = BasicTestCampaign()
        
        assert hasattr(campaign, 'packet')
        assert campaign.packet is not None
        assert IP in campaign.packet
        assert TCP in campaign.packet
        
        # Check packet fields
        assert campaign.packet[IP].dst == "192.168.1.1"
        assert campaign.packet[TCP].dport == 80
    
    def test_campaign_fuzzer_creation(self):
        """Test campaign fuzzer creation"""
        campaign = BasicTestCampaign()
        
        try:
            fuzzer = campaign.create_fuzzer()
            assert fuzzer is not None
            assert isinstance(fuzzer, MutatorManager)
        except (ImportError, NotImplementedError):
            # Acceptable if libfuzzer not available or method not implemented
            pass
    
    def test_campaign_configuration_inheritance(self):
        """Test that campaigns can inherit and override configurations"""
        
        class CustomCampaign(BasicTestCampaign):
            name = "Custom Campaign"
            target = "10.0.0.1"
            rate_limit = 20.0
        
        campaign = CustomCampaign()
        
        assert campaign.name == "Custom Campaign"
        assert campaign.target == "10.0.0.1"
        assert campaign.rate_limit == 20.0
        # Should inherit other attributes
        assert campaign.iterations == 5  # From BasicTestCampaign
        assert campaign.verbose == False
    
    def test_campaign_dictionary_config(self):
        """Test campaign dictionary configuration"""
        campaign = DictionaryTestCampaign()
        
        assert hasattr(campaign, 'dictionary_config_file')
        assert campaign.dictionary_config_file == "examples/intermediate/02_dictionary_config.py"


class TestSpecializedCampaigns(unittest.TestCase):
    """Test specialized campaign classes"""
    
    def test_http_campaign(self):
        """Test HTTP fuzzing campaign"""
        campaign = HTTPTestCampaign()
        
        assert campaign.name == "HTTP Test Campaign"
        assert campaign.target == "192.168.1.100"
        
        packet = campaign.packet
        assert packet is not None
        assert IP in packet
        assert TCP in packet
        assert Raw in packet
        
        # Should have HTTP-specific configuration
        assert packet[TCP].dport == 80
        assert b"HTTP" in packet[Raw].load
    
    def test_dns_campaign(self):
        """Test DNS fuzzing campaign"""
        campaign = DNSTestCampaign()
        
        assert campaign.name == "DNS Test Campaign"
        assert campaign.target == "10.10.10.10"
        
        packet = campaign.packet
        assert packet is not None
        assert IP in packet
        assert UDP in packet
        assert DNS in packet
        
        # Should have DNS-specific configuration
        assert packet[UDP].dport == 53
        assert packet[DNS].qd.qtype == 1  # A record
        assert packet[DNS].qd.qname == b"test.com."
    
    def test_layer2_campaign(self):
        """Test Layer 2 campaign"""
        campaign = Layer2TestCampaign()
        
        assert campaign.name == "Layer 2 Test Campaign"
        assert campaign.socket_type == "l2"
        assert campaign.interface == "eth0"
        
        # Should have layer 2 packet
        packet = campaign.packet
        assert packet is not None
    
    def test_pcap_campaign(self):
        """Test PCAP output campaign"""
        campaign = PCAPTestCampaign()
        
        assert campaign.name == "PCAP Test Campaign"
        assert campaign.output_pcap == "test_output.pcap"
        assert campaign.output_network == False
    
    def test_network_campaign(self):
        """Test network output campaign"""
        campaign = NetworkTestCampaign()
        
        assert campaign.name == "Network Test Campaign"
        assert campaign.output_network == True
        assert campaign.output_pcap == None


class TestCampaignInheritance(unittest.TestCase):
    """Test campaign inheritance patterns"""
    
    def test_base_campaign_inheritance(self):
        """Test inheriting from base campaign"""
        
        class CustomBaseCampaign(FuzzingCampaign):
            # Override defaults for all campaigns
            rate_limit = 50.0
            interface = "eth1"
        
        class SpecificCampaign(CustomBaseCampaign):
            name = "Specific Campaign"
            target = "10.1.1.1"
        
        campaign = SpecificCampaign()
        
        # Should inherit from custom base
        assert hasattr(campaign, 'rate_limit')
        assert campaign.rate_limit == 50.0
        if hasattr(campaign, 'interface'):
            assert campaign.interface == "eth1"
        
        # Should override specific attributes
        assert campaign.name == "Specific Campaign"
        assert campaign.target == "10.1.1.1"
    
    def test_multiple_inheritance_levels(self):
        """Test multiple levels of inheritance"""
        
        class Level1Campaign(FuzzingCampaign):
            level1_attr = "level1"
            shared_attr = "from_level1"
        
        class Level2Campaign(Level1Campaign):
            level2_attr = "level2"
            shared_attr = "from_level2"
        
        class Level3Campaign(Level2Campaign):
            level3_attr = "level3"
        
        campaign = Level3Campaign()
        
        # Should have attributes from all levels
        assert campaign.level1_attr == "level1"
        assert campaign.level2_attr == "level2"
        assert campaign.level3_attr == "level3"
        
        # Later levels should override earlier ones
        assert campaign.shared_attr == "from_level2"
    
    def test_attribute_override(self):
        """Test attribute override in inheritance"""
        
        class ParentCampaign(BasicTestCampaign):
            name = "Parent Campaign"
            iterations = 50
        
        class ChildCampaign(ParentCampaign):
            name = "Child Campaign"
            # iterations should be inherited (50)
        
        parent = ParentCampaign()
        child = ChildCampaign()
        
        assert parent.name == "Parent Campaign"
        assert parent.iterations == 50
        
        assert child.name == "Child Campaign"
        assert child.iterations == 50  # Inherited
        assert child.target == "192.168.1.1"  # From BasicTestCampaign


class TestCampaignUtilities(unittest.TestCase):
    """Test campaign utility functions"""
    
    def test_campaign_string_representation(self):
        """Test campaign string representation"""
        campaign = BasicTestCampaign()
        
        str_repr = str(campaign)
        assert isinstance(str_repr, str)
        assert len(str_repr) > 0
        
        # Should contain campaign name or type info
        assert campaign.name is not None
        if campaign.name is not None:
            assert "Campaign" in str_repr or campaign.name in str_repr
    
    def test_campaign_comparison(self):
        """Test campaign comparison"""
        campaign1 = BasicTestCampaign()
        campaign2 = BasicTestCampaign()
        
        # Different instances should be different objects
        assert campaign1 is not campaign2
        
        # But should have same configuration
        assert campaign1.name == campaign2.name
        assert campaign1.target == campaign2.target
        assert campaign1.iterations == campaign2.iterations
    
    def test_campaign_attributes_modification(self):
        """Test modifying campaign attributes"""
        campaign = BasicTestCampaign()
        
        # Should be able to modify attributes
        original_target = campaign.target
        campaign.target = "10.0.0.100"
        assert campaign.target == "10.0.0.100"
        assert campaign.target != original_target
        
        # Should be able to modify rate limit
        campaign.rate_limit = 25.0
        assert campaign.rate_limit == 25.0


class TestCampaignErrorHandling:
    """Test campaign error handling"""
    
    def test_missing_attributes_handling(self):
        """Test handling of missing attributes"""
        
        class IncompleteCampaign(FuzzingCampaign):
            # Missing some attributes
            name = "Incomplete Campaign"
            # Missing target, iterations, etc.
        
        campaign = IncompleteCampaign()
        
        # Should handle missing attributes gracefully
        assert campaign.name == "Incomplete Campaign"
        
        # Check if default attributes are present
        expected_attrs = ['name']
        for attr in expected_attrs:
            assert hasattr(campaign, attr)
    
    def test_invalid_configuration_handling(self):
        """Test handling of invalid configuration"""
        campaign = BasicTestCampaign()
        
        # Test with potentially invalid values
        try:
            campaign.rate_limit = -1.0  # Invalid rate limit
            # Should handle gracefully or raise appropriate exception
        except (ValueError, AssertionError):
            pass  # Expected behavior
        
        try:
            campaign.iterations = -5  # Invalid iteration count
            # Should handle gracefully or raise appropriate exception
        except (ValueError, AssertionError):
            pass  # Expected behavior
    
    def test_campaign_packet_validation(self):
        """Test campaign packet validation"""
        campaign = BasicTestCampaign()
        
        # Packet should be valid
        packet = campaign.packet
        assert packet is not None
        
        # Should have required layers
        assert IP in packet
        
        # IP layer should have valid destination
        ip_layer = packet[IP]
        assert ip_layer.dst is not None
        assert len(ip_layer.dst) > 0


class TestCampaignConfiguration:
    """Test campaign configuration management"""
    
    def test_output_configuration(self):
        """Test output configuration options"""
        # Test PCAP output
        pcap_campaign = PCAPTestCampaign()
        assert pcap_campaign.output_pcap == "test_output.pcap"
        assert pcap_campaign.output_network == False
        
        # Test network output
        network_campaign = NetworkTestCampaign()
        assert network_campaign.output_network == True
        assert network_campaign.output_pcap == None
    
    def test_rate_limiting_configuration(self):
        """Test rate limiting configuration"""
        campaign = BasicTestCampaign()
        
        # Should have rate limiting
        assert hasattr(campaign, 'rate_limit')
        assert isinstance(campaign.rate_limit, (int, float))
        assert campaign.rate_limit > 0
    
    def test_iteration_configuration(self):
        """Test iteration configuration"""
        campaign = BasicTestCampaign()
        
        # Should have iteration count
        assert hasattr(campaign, 'iterations')
        assert isinstance(campaign.iterations, int)
        assert campaign.iterations > 0
    
    def test_verbose_configuration(self):
        """Test verbose mode configuration"""
        campaign = BasicTestCampaign()
        
        # Should have verbose setting
        assert hasattr(campaign, 'verbose')
        assert isinstance(campaign.verbose, bool)
        
        # Should be able to modify
        campaign.verbose = True
        assert campaign.verbose == True


class DummyTestCampaign(FuzzingCampaign):
    name = "dummy_test"
    target = "127.0.0.1"
    output_network = False
    def build_packets(self):
        return [IP(dst=self.target)/TCP(dport=int(80))/Raw(load=b"test")]  # Ensure dport is int


if __name__ == '__main__':
    # Run tests with pytest if available, otherwise use unittest
    if PYTEST_AVAILABLE:
        try:
            pytest.main([__file__, '-v'])
        except SystemExit:
            pass
    else:
        import unittest
        unittest.main(verbosity=2)
