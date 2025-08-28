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

class QuickStartCampaign(FuzzingCampaign):
    """Minimal fuzzing campaign - just the essentials."""
    name = "Quick Start"
    target = "192.168.1.100"
    iterations = 1000
    verbose = False  # Disable verbose mode to show the difference
    socket_type = 'managed_udp'  # Real TCP connections with automatic handshake
    packet = (
              HTTP() / 
              HTTPRequest(Path=b"/", Method=b"GET"))
    report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']  # All formats

# Register campaign(s) for framework and CLI discovery
CAMPAIGNS = [QuickStartCampaign]
