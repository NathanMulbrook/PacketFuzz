#!/usr/bin/env python3
"""
Basic Example 2: FuzzField Basics - Different Value Types

Shows how to use FuzzField with different data types and basic configuration options.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class IntegerFuzzCampaign(FuzzingCampaign):
    """Demonstrates integer field fuzzing."""
    name = "Integer Fuzzing"
    target = "192.168.1.100"
    iterations = 5
    output_pcap = "basic_integer_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(
            dport=FuzzField(values=[80, 443, 8080, 9000]),
            sport=FuzzField(values=[1024, 2048, 4096, 8192])
        )
    )

class StringFuzzCampaign(FuzzingCampaign):
    """Demonstrates string field fuzzing."""
    name = "String Fuzzing"
    target = "8.8.8.8"
    iterations = 5
    output_pcap = "basic_string_fuzz.pcap"
    
    packet = (
        IP(dst="8.8.8.8") / 
        UDP(dport=53) / 
        DNS(qd=DNSQR(qname=FuzzField(values=["example.com", "test.org", "fuzz.local"])))
    )

class BytesFuzzCampaign(FuzzingCampaign):
    """Demonstrates bytes/payload fuzzing."""
    name = "Bytes Fuzzing"
    target = "192.168.1.100"
    iterations = 5
    output_pcap = "basic_bytes_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=80) / 
        Raw(load=FuzzField(values=[
            b"GET / HTTP/1.1\r\n\r\n",
            b"POST /api HTTP/1.1\r\n\r\n",
            b"PUT /data HTTP/1.1\r\n\r\n"
        ]))
    )

# Campaign list for easy execution
CAMPAIGNS = [
    IntegerFuzzCampaign,
    StringFuzzCampaign,
    BytesFuzzCampaign
]

def main():
    print("=== Basic Example 2: FuzzField Basics ===")
    print("Demonstrates FuzzField with different data types")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        print(f"Running {campaign.name}...")
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"YES {campaign.name} completed - {campaign.output_pcap}")
        else:
            print(f"NO {campaign.name} failed")
        print()
    
    success_count = sum(results)
    print(f"Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    return all(results)

if __name__ == "__main__":
    main()
