#!/usr/bin/env python3
"""
Intermediate Example 3: PCAP Regression - Replay and Analysis

Shows how to use existing PCAP files for regression testing and fuzzing
with layer extraction and repackaging.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap
  

from packetfuzz.pcapfuzz import PcapFuzzCampaign

class RegressionTestCampaign(PcapFuzzCampaign):
    """Pure regression testing - replay without fuzzing."""
    name = "Regression Replay"
    pcap_folder = "regression_samples/"
    fuzz_mode = "none"  # No fuzzing
    target = "192.168.1.100"
    iterations = 2  # Reduced for faster test execution
    output_pcap = "intermediate_regression_replay.pcap"
    verbose = True

class HTTPPayloadExtractionCampaign(PcapFuzzCampaign):
    """Extract HTTP payloads and apply field-based fuzzing."""
    name = "HTTP Payload Extraction"
    pcap_folder = "regression_samples/"
    extract_layer = "TCP"  # Extract TCP payload
    repackage_in = "IP/TCP"  # New headers
    fuzz_mode = "field"  # Dictionary-based fuzzing
    target = "192.168.1.100"
    iterations = 2  # Reduced for faster test execution
    output_pcap = "intermediate_http_extraction.pcap"
    verbose = True

class DNSQueryFuzzCampaign(PcapFuzzCampaign):
    """Extract and fuzz DNS queries."""
    name = "DNS Query Fuzzing"
    pcap_folder = "regression_samples/"
    extract_layer = "UDP"  # Extract UDP payload
    repackage_in = "IP/UDP"  # New headers
    fuzz_mode = "field"  # Field-aware fuzzing
    target = "10.10.10.10"
    iterations = 2  # Reduced for faster test execution
    output_pcap = "intermediate_dns_extraction.pcap"
    verbose = True

class BinaryProtocolCampaign(PcapFuzzCampaign):
    """Binary-level fuzzing of unknown protocols."""
    name = "Binary Protocol Fuzzing"
    pcap_folder = "regression_samples/"
    extract_layer = "UDP"
    repackage_in = "IP/UDP"
    fuzz_mode = "binary"  # Binary mutations
    target = "192.168.1.200"
    iterations = 2  # Reduced for faster test execution
    output_pcap = "intermediate_binary_fuzz.pcap"
    verbose = True

def create_sample_pcaps():
    """Create sample PCAP files for testing."""
    sample_dir = "regression_samples"
    if not os.path.exists(sample_dir):
        os.makedirs(sample_dir)
    
    # Create sample HTTP traffic
    http_packets = [
        IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=12345, dport=80)/b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        IP(src="93.184.216.34", dst="192.168.1.10")/TCP(sport=80, dport=12345)/b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ]
    wrpcap(f"{sample_dir}/http_sample.pcap", http_packets)
    
    # Create sample DNS traffic
    dns_packets = [
        IP(src="192.168.1.10", dst="10.10.10.10")/UDP(sport=54321, dport=53)/b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
        IP(src="10.10.10.10", dst="192.168.1.10")/UDP(sport=53, dport=54321)/b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    ]
    wrpcap(f"{sample_dir}/dns_sample.pcap", dns_packets)
    
    print("[PASS] Created sample PCAP files in regression_samples/")

# Campaign registry
CAMPAIGNS = [
    RegressionTestCampaign,
    HTTPPayloadExtractionCampaign,
    DNSQueryFuzzCampaign,
    BinaryProtocolCampaign
]

def main():
    print("=== Intermediate Example 3: PCAP Regression ===")
    print("Demonstrates PCAP-based regression testing and fuzzing")
    print()
    
    # Create sample PCAPs if needed
    if not os.path.exists("regression_samples/"):
        print("Setting up regression samples...")
        create_sample_pcaps()
        print()
    
    print("PCAP Fuzzing Modes:")
    print("   • none: Pure regression replay")
    print("   • field: Dictionary-based field fuzzing")
    print("   • binary: Binary-level mutations")
    print("   • both: Combined field + binary fuzzing")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"Running {campaign.name}")
        print(f"   Mode: {campaign.fuzz_mode}")
        print(f"   Target: {campaign.target}")
        
        if hasattr(campaign, 'extract_layer') and campaign.extract_layer:
            print(f"   Extract: {campaign.extract_layer} → {campaign.repackage_in}")
        
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"   [PASS] Success - {campaign.output_pcap}")
        else:
            print(f"   ✗ Failed")
        print()
    
    success_count = sum(results)
    print(f"Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    print("\nLayer Extraction Process:")
    print("   Original PCAP → Extract Layer → Repackage → Fuzz → Output")
    print("   Example: Ethernet/IP/TCP/HTTP → TCP → IP/TCP → Field Fuzz → PCAP")
    
    return all(results)

if __name__ == "__main__":
    main()
