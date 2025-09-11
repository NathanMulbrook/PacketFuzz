#!/usr/bin/env python3
"""
Basic Example 1: Quick Start 

The simplest possible fuzzing example to get started:
- Basic HTTP fuzzing campaign
- Field filtering (fields_to_fuzz)
- Safe network-disabled mode for testing

To run this example:
    python -m packetfuzz examples/basic/01_quick_start.py --disable-network
"""

# Third-party imports
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP

# Local imports
from packetfuzz.fuzzing_framework import FuzzingCampaign
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class QuickStartCampaign(FuzzingCampaign):
    """Simple HTTP fuzzing demonstrating field filtering.
    
    Note: __slots__ = () is required for typo prevention inheritance.
    """
    __slots__ = ()  # Required to inherit typo prevention from FuzzingCampaign
    
    def __init__(self):
        super().__init__()
        self.name = "Quick Start"
        self.socket_config = RawIPConfig(target="127.0.0.1")
        self.fields_to_fuzz = ["Path", "Host"]  # Only fuzz these specific fields
        self.iterations = 25
        self.output_network = False
        self.verbose = True
        self.packet = (
            IP() /
            TCP(dport=80) /
            HTTP() / 
            HTTPRequest(Path=b"/api/test", Method=b"GET", Host=b"example.com")
        )

class MultiLayerFieldFiltering(FuzzingCampaign):
    """Multi-layer packet showing layer-based field filtering."""
    __slots__ = ()  # Required to inherit typo prevention from FuzzingCampaign
    
    def __init__(self):
        super().__init__()
        self.name = "Multi-Layer Field Filtering"
        self.socket_config = RawIPConfig(target="127.0.0.1")
        self.iterations = 25
        self.output_network = False
        self.verbose = True
        self.packet = (
            IP(dst="127.0.0.1") /
            TCP(dport=80) /
            HTTP() / 
            HTTPRequest(Path=b"/test", Method=b"POST", Host=b"localhost")
        )


# Register campaign(s) for framework and CLI discovery
CAMPAIGNS = [QuickStartCampaign, MultiLayerFieldFiltering]

