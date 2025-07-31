#!/usr/bin/env python3
"""
Basic PCAP Example - PCAP-Based Fuzzing and Regression Testing

This example shows how to use PCAP files for regression testing and fuzzing.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pcapfuzz import PcapFuzzCampaign

class BasicRegressionCampaign(PcapFuzzCampaign):
    """Basic regression testing - replay packets without fuzzing."""
    name = "Basic Regression Test"
    pcap_folder = "regression_samples/"
    fuzz_mode = "none"  # No fuzzing - pure regression testing
    target = "192.168.1.100"
    output_network = False
    output_pcap = "regression_replay.pcap"
    verbose = True

class BasicPayloadExtractionCampaign(PcapFuzzCampaign):
    """Extract UDP payloads and fuzz them."""
    name = "UDP Payload Extraction"
    pcap_folder = "regression_samples/"
    extract_layer = "UDP"  # Extract UDP payload
    repackage_in = "IP/UDP"  # Repackage in new headers
    fuzz_mode = "field"  # Use dictionary-based fuzzing
    target = "192.168.1.100"
    iterations = 3
    output_network = False
    output_pcap = "udp_payload_fuzz.pcap"
    verbose = True

# List of PCAP campaigns
campaigns = [
    BasicRegressionCampaign,
    BasicPayloadExtractionCampaign
]

def main():
    """Run basic PCAP examples."""
    print("=== Basic PCAP Examples ===")
    print()
    print("This example demonstrates:")
    print("1. Pure regression testing (no fuzzing)")
    print("2. Layer extraction and payload repackaging")
    print("3. Different fuzzing modes")
    print()
    
    # First, create sample PCAP files if they don't exist
    if not os.path.exists("regression_samples/"):
        print("Creating sample PCAP files...")
        from utils.create_sample_pcaps import create_sample_pcaps
        create_sample_pcaps()
        print()
    
    results = []
    
    for campaign_class in campaigns:
        campaign = campaign_class()
        print(f"\n--- Running {campaign.name} ---")
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"YES {campaign.name} completed successfully")
        else:
            print(f"NO {campaign.name} failed")
    
    print(f"\n=== Summary ===")
    print(f"PCAP campaigns run: {len(campaigns)}")
    print(f"Successful: {sum(results)}")
    print(f"Failed: {len(results) - sum(results)}")
    
    return all(results)

if __name__ == "__main__":
    main()
