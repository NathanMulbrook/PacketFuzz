#!/usr/bin/env python3
"""
Basic Example 1: Quick Start - Minimal Effort Fuzzing

The simplest possible fuzzing example - just 5 lines of configuration.
Perfect for getting started quickly.

To run this example with the PacketFuzz CLI:
    python3 -m fuzzing_framework.examples.basic.01_quick_start
or simply:
    python3 examples/basic/01_quick_start.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest

class QuickStartCampaign(FuzzingCampaign):
    """Minimal fuzzing campaign - just the essentials."""
    name = "Quick Start"
    target = "192.168.1.100"
    iterations = 1000
    verbose = False
    output_pcap = "basic_quick_start.pcap"
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET")

# Register campaign(s) for framework and CLI discovery
CAMPAIGNS = [QuickStartCampaign]
