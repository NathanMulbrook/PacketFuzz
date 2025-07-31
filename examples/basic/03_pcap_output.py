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
    output_network = False  # No packet sending, PCAP-only mode
    
    def get_packet(self):
        # Define the packet with proper integer values for ICMP type
        pkt = IP(dst="192.168.1.100") / ICMP()
        # Configure field after packet creation
        pkt[ICMP].field_fuzz("type").default_values = [8, 0, 3, 11]  # Different ICMP types
        return pkt

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
        if campaign.output_pcap:
            pcap_path = os.path.join("pcaps", campaign.output_pcap)
            if os.path.exists(pcap_path):
                analyze_pcap(pcap_path)
            else:
                print(f"⚠️  PCAP file not found for analysis at {pcap_path}")
        else:
            print("⚠️  No PCAP output path specified")
    else:
        print("✗ Campaign failed")
    
    return result

if __name__ == "__main__":
    main()
