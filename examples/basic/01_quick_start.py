#!/usr/bin/env python3
"""
Basic Example 1: Quick Start - Minimal Effort Fuzzing

The simplest possible fuzzing example - just 5 lines of configuration.
Perfect for getting started quickly.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP

class QuickStartCampaign(FuzzingCampaign):
    """Minimal fuzzing campaign - just the essentials."""
    name = "Quick Start"
    target = "192.168.1.100"
    iterations = 10
    output_pcap = "basic_quick_start.pcap"
    
    packet = IP(dst="192.168.1.100") / TCP(dport=FuzzField(values=[80, 443, 8080]))

def main():
    print("=== Basic Example 1: Quick Start ===")
    print("Minimal fuzzing example with just 5 lines of configuration")
    print()
    
    campaign = QuickStartCampaign()
    print(f"Campaign: {campaign.name}")
    print(f"Target: {campaign.target}")
    print(f"Iterations: {campaign.iterations}")
    print(f"Output: {campaign.output_pcap}")
    print()
    
    print("Executing campaign...")
    result = campaign.execute()
    
    if result:
        print("Success! Packets saved to:", campaign.output_pcap)
    else:
        print("Campaign failed")
    
    return result

if __name__ == "__main__":
    main()
