#!/usr/bin/env python3
"""
Basic Example 1: Quick Start - Minimal Effort Fuzzing

The simplest possible fuzzing example - just 5 lines of configuration.
Perfect for getting started quickly.

To run this example with the PacketFuzz CLI:
    python -m packetfuzz examples/basic/01_quick_start.py
"""

# Third-party imports
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP

# Local imports
from packetfuzz.fuzzing_framework import FuzzField, FuzzingCampaign
from packetfuzz.sockets.managed_udp_socket import ManagedUDPConfig
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class QuickStartCampaign(FuzzingCampaign):
    """Minimal fuzzing campaign - just the essentials."""
    name = "Quick Start"
    socket_config = ManagedUDPConfig(target="192.168.1.100", port=53)
    iterations = 10
    verbose = False  # Disable verbose mode to show the difference
    packet = (
              HTTP() / 
              HTTPRequest(Path=b"/", Method=b"GET"))
    report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']  # All formats

class QuickStartCampaignMultilayer(FuzzingCampaign):
    """Minimal fuzzing campaign - just the essentials."""
    name = "Quick Start Multilayer"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 10
    verbose = False  # Disable verbose mode to show the difference
    packet = (IP() /
                TCP() /
              HTTP() / 
              HTTPRequest(Path=b"/", Method=b"GET"))
    report_formats = ['all']  # All formats


# Register campaign(s) for framework and CLI discovery
CAMPAIGNS = [QuickStartCampaign
             , QuickStartCampaignMultilayer
            ]
