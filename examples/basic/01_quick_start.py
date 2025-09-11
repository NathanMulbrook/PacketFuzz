#!/usr/bin/env python3
"""
Basic Example 1: Quick Start - Modern PacketFuzz Features

The simplest possible fuzzing example showcasing the latest features:
- Enhanced fuzz history logging with hierarchical packet breakdown
- Improved report generation with multiple formats
- Optimized performance for faster execution

To run this example with the PacketFuzz CLI:
    python -m packetfuzz examples/basic/01_quick_start.py --disable-network -vvv
    
CLI Features:
    --disable-network          # Safe testing mode (no network traffic)
    -vvv                      # Enhanced verbose logging with packet breakdown
    --report-formats all      # Generate all available report formats
    --max-iterations N        # Limit iterations for quick testing
"""

# Third-party imports
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP

# Local imports
from packetfuzz.fuzzing_framework import FuzzingCampaign
from packetfuzz.sockets.managed_udp_socket import ManagedUDPConfig
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class QuickStartCampaign(FuzzingCampaign):
    """Simple HTTP fuzzing with enhanced logging."""
    name = "Quick Start"
    socket_config = ManagedUDPConfig(target="192.168.1.100", port=80)
    fields_to_fuzz = ["Path", "Host"]
    iterations = 50
    verbose = True
    packet = (
        HTTP() / 
        HTTPRequest(Path=b"/", Method=b"GET", Host=b"example.com")
    )
    report_formats = ['json', 'html', "markdown"]  # Core formats for demo

class QuickStartMultilayer(FuzzingCampaign):
    """Multi-layer packet fuzzing showcasing hierarchical packet breakdown."""
    name = "Quick Start Multilayer"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 50
    verbose = True
    packet = (
        IP(dst="127.0.0.1") /
        TCP(dport=80) /
        HTTP() / 
        HTTPRequest(Path=b"/test", Method=b"GET", Host=b"localhost")
    )
    report_formats = ['all']  # Demonstrate all available formats


# Register campaign(s) for framework and CLI discovery
CAMPAIGNS = [QuickStartCampaign, QuickStartMultilayer]

