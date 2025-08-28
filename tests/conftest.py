#!/usr/bin/env python3
"""
Shared test fixtures and utilities for the PacketFuzz test suite.

This module provides common pytest fixtures, utilities, and helper functions
that are used across multiple test modules.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

# Add the parent directory to sys.path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, ARP, Raw


def cleanup_test_files():
    """
    Clean up any test files that may have been left behind.
    This is a utility function that can be called from any test.
    """
    project_root = Path(__file__).parent.parent
    
    # Files to clean up in the main directory
    cleanup_files = [
        "test.pcap",
        "fallback_test.pcap", 
        "test_output.pcap",
        "test_packets_0.pcap",
        "test_packets_1.pcap", 
        "test_packets_2.pcap",
        # Legacy fuzz field reports (should be in logs/ now)
        "fuzz_fields_input_report.txt",
        "fuzz_fields_output_report.txt"
    ]
    
    # Clean up files in project root
    for filename in cleanup_files:
        filepath = project_root / filename
        if filepath.exists():
            try:
                filepath.unlink()
            except Exception:
                pass  # Ignore cleanup errors
    
    # Clean up crash log directories and their contents
    crash_dirs = [
        project_root / "crash_logs",
        project_root / "examples" / "crash_logs"
    ]
    
    for crash_dir in crash_dirs:
        if crash_dir.exists() and crash_dir.is_dir():
            try:
                # Remove all files in crash logs directory
                for crash_file in crash_dir.iterdir():
                    try:
                        if crash_file.is_file():
                            crash_file.unlink()
                        elif crash_file.is_dir():
                            # Remove subdirectories recursively  
                            shutil.rmtree(crash_file)
                    except Exception:
                        # Ignore permission errors
                        pass
            except Exception:
                # Ignore permission errors on directory access
                pass
    
    # Clean up fuzz field reports from logs directory
    logs_dir = project_root / "logs"
    if logs_dir.exists() and logs_dir.is_dir():
        log_cleanup_files = [
            "fuzz_fields_input_report.txt",
            "fuzz_fields_output_report.txt"
        ]
        
        for log_file in log_cleanup_files:
            log_path = logs_dir / log_file
            if log_path.exists():
                try:
                    log_path.unlink()
                except Exception:
                    # Ignore permission errors
                    pass


@pytest.fixture(autouse=True)
def test_cleanup():
    """
    Automatically clean up test artifacts before and after each test.
    This fixture runs automatically for all tests when pytest is available.
    """
    # Cleanup before test
    cleanup_test_files()
    
    yield  # Run the test
    
    # Cleanup after test
    cleanup_test_files()


# Test Campaign Classes
class BasicTestCampaign(FuzzingCampaign):
    """Basic test campaign for unit tests"""
    name = "Basic Test Campaign"
    target = "192.168.1.1"
    iterations = 5
    rate_limit = 100.0
    verbose = False
    output_network = False
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.1") / TCP(dport=80)


class HTTPTestCampaign(FuzzingCampaign):
    """HTTP-focused test campaign"""
    name = "HTTP Test Campaign"
    target = "192.168.1.100"
    iterations = 10
    rate_limit = 50.0
    verbose = False
    output_network = False
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.100") / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        
        # Configure embedded fuzzing
        tcp_layer = self.packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        tcp_layer.field_fuzz('dport').description = "HTTP ports"


class DNSTestCampaign(FuzzingCampaign):
    """DNS-focused test campaign"""
    name = "DNS Test Campaign"
    target = "10.10.10.10"
    iterations = 5
    rate_limit = 20.0
    verbose = False
    output_network = False
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="10.10.10.10") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="test.com"))
        
        # Configure embedded fuzzing
        dns_layer = self.packet[DNS]
        dns_layer.field_fuzz('id').default_values = [0x1234, 0x5678]
        dns_layer.field_fuzz('id').description = "DNS transaction IDs"


class Layer2TestCampaign(FuzzingCampaign):
    """Layer 2 test campaign"""
    name = "Layer 2 Test Campaign"
    target = "192.168.1.0/24"
    socket_type = "raw_ethernet"
    interface = "eth0"
    iterations = 3
    rate_limit = 10.0
    verbose = False
    output_network = False
    
    def __init__(self):
        super().__init__()
        self.packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
        
        # Configure embedded fuzzing
        arp_layer = self.packet[ARP]
        arp_layer.field_fuzz('pdst').default_values = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        arp_layer.field_fuzz('pdst').description = "ARP target IPs"


class PCAPTestCampaign(FuzzingCampaign):
    """Test campaign for PCAP output testing"""
    name = "PCAP Test Campaign"
    target = "192.168.1.50"
    iterations = 5
    rate_limit = 20.0
    verbose = False
    output_network = False
    output_pcap = "test_output.pcap"
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.50") / TCP(dport=22)


class NetworkTestCampaign(FuzzingCampaign):
    """Test campaign for network output testing"""
    name = "Network Test Campaign"
    target = "192.168.1.60"
    iterations = 3
    rate_limit = 5.0
    verbose = False
    output_network = True
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.60") / TCP(dport=443)


class DictionaryTestCampaign(FuzzingCampaign):
    """Test campaign with custom dictionary configuration"""
    name = "Dictionary Test Campaign"
    target = "192.168.1.70"
    iterations = 5
    rate_limit = 10.0
    verbose = False
    output_network = False
    dictionary_config_file = "examples/intermediate/02_dictionary_config.py"
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.70") / TCP(dport=80)


class DummyConftestCampaign(FuzzingCampaign):
    name = "dummy_conftest"
    target = "127.0.0.1"
    output_network = False
    def build_packets(self):
        return [IP(dst=self.target)/UDP(dport=int(53))/Raw(load=b"test")]  # Ensure dport is int


# Test Fixtures
@pytest.fixture
def basic_campaign():
    """Fixture providing a basic test campaign"""
    return BasicTestCampaign()


@pytest.fixture
def http_campaign():
    """Fixture providing an HTTP test campaign"""
    return HTTPTestCampaign()


@pytest.fixture
def dns_campaign():
    """Fixture providing a DNS test campaign"""
    return DNSTestCampaign()


@pytest.fixture
def layer2_campaign():
    """Fixture providing a Layer 2 test campaign"""
    return Layer2TestCampaign()


@pytest.fixture
def pcap_campaign():
    """Fixture providing a PCAP test campaign"""
    return PCAPTestCampaign()


@pytest.fixture
def network_campaign():
    """Fixture providing a network test campaign"""
    return NetworkTestCampaign()


@pytest.fixture
def dictionary_campaign():
    """Fixture providing a dictionary test campaign"""
    return DictionaryTestCampaign()


@pytest.fixture
def temp_pcap_file():
    """Fixture providing a temporary PCAP file path"""
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        temp_path = f.name
    yield temp_path
    # Cleanup
    try:
        os.unlink(temp_path)
    except OSError:
        pass


@pytest.fixture
def temp_config_file():
    """Fixture providing a temporary configuration file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('''
from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.layers.inet import IP, TCP

class TempTestCampaign(FuzzingCampaign):
    name = "Temporary Test Campaign"
    target = "192.168.1.200"
    iterations = 2
    output_network = False
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst="192.168.1.200") / TCP(dport=80)

CAMPAIGNS = [TempTestCampaign]
''')
        temp_path = f.name
    yield temp_path
    # Cleanup
    try:
        os.unlink(temp_path)
    except OSError:
        pass


# Test Utilities
def create_test_packet(packet_type: str = "tcp") -> Any:
    """Create a test packet of the specified type"""
    if packet_type == "tcp":
        return IP(dst="192.168.1.1") / TCP(dport=80)
    elif packet_type == "udp":
        return IP(dst="192.168.1.1") / UDP(dport=53)
    elif packet_type == "dns":
        return IP(dst="10.10.10.10") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="test.com"))
    elif packet_type == "arp":
        return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    else:
        raise ValueError(f"Unknown packet type: {packet_type}")


def configure_packet_fuzzing(packet: Any, field_configs: Dict[str, Dict[str, Any]]) -> None:
    """Configure fuzzing for a packet with the given field configurations"""
    for layer_field, config in field_configs.items():
        layer_name, field_name = layer_field.split('.')
        layer = packet.getlayer(layer_name)
        if layer:
            field_proxy = layer.field_fuzz(field_name)
            for attr, value in config.items():
                setattr(field_proxy, attr, value)


def validate_campaign_config(campaign: FuzzingCampaign) -> List[str]:
    """Validate a campaign configuration and return any issues"""
    issues = []
    
    if not campaign.name:
        issues.append("Campaign name is required")
    
    if not campaign.target:
        issues.append("Campaign target is required")
    
    if campaign.iterations <= 0:
        issues.append("Campaign iterations must be positive")
    
    if campaign.rate_limit <= 0:
        issues.append("Campaign rate_limit must be positive")
    
    if not campaign.packet:
        issues.append("Campaign packet is required")
    
    return issues


# Registry of all test campaigns for discovery
TEST_CAMPAIGNS = [
    BasicTestCampaign,
    HTTPTestCampaign,
    DNSTestCampaign,
    Layer2TestCampaign,
    PCAPTestCampaign,
    NetworkTestCampaign,
    DictionaryTestCampaign,
    DummyConftestCampaign,
]
