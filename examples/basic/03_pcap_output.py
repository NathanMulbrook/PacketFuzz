#!/usr/bin/env python3
"""
Basic Example 3: PCAP Output - Simple Packet Analysis

Shows how to generate PCAP files and basic packet analysis.
"""

import sys
import os
from scapy.layers.inet import IP, ICMP
from scapy.utils import rdpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class PCAPOutputCampaign(FuzzingCampaign):
    """Simple campaign focused on PCAP output."""
    name = "PCAP Output Demo"
    target = "192.168.1.100"
    iterations = 10
    output_pcap = "basic_pcap_demo.pcap"
    verbose = True
    
    packet = (
        IP(dst="192.168.1.100") / 
        ICMP(type=FuzzField(values=[8, 0, 3, 11]))  # Different ICMP types
    )

def analyze_pcap(filename):
    """Simple PCAP analysis function."""
    try:
        packets = rdpcap(filename)
        print(f"📊 PCAP Analysis: {filename}")
        print(f"   Total packets: {len(packets)}")
        
        # Count packet types
        icmp_types = {}
        for packet in packets:
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1
        
        print(f"   ICMP types: {icmp_types}")
        print(f"   Average packet size: {sum(len(p) for p in packets) / len(packets):.1f} bytes")
        
    except Exception as e:
        print(f"   Error analyzing PCAP: {e}")

def main():
    print("=== Basic Example 3: PCAP Output ===")
    print("Demonstrates PCAP file generation and analysis")
    print()
    
    # Create and run campaign
    campaign = PCAPOutputCampaign()
    print(f"Running {campaign.name}...")
    print(f"Target: {campaign.target}")
    print(f"Iterations: {campaign.iterations}")
    print()
    
    result = campaign.execute()
    
    if result:
        print("✓ Campaign completed successfully!")
        print()
        
        # Analyze the generated PCAP
        if campaign.output_pcap and os.path.exists(campaign.output_pcap):
            analyze_pcap(campaign.output_pcap)
        else:
            print("⚠️  PCAP file not found for analysis")
    else:
        print("✗ Campaign failed")
    
    return result

if __name__ == "__main__":
    main()
