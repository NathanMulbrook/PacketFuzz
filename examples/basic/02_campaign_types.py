#!/usr/bin/env python3
"""
Basic Campaign Example - Understanding Campaign Structure

This example shows how to create and structure basic fuzzing campaigns
using the campaign framework.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class BasicHTTPCampaign(FuzzingCampaign):
    """Basic HTTP fuzzing campaign."""
    name = "Basic HTTP Fuzzing"
    target = "192.168.1.100"
    iterations = 5
    output_network = False
    output_pcap = "basic_http.pcap"
    verbose = True
    
    packet = (
        IP(dst="192.168.1.100") /
        TCP(dport=FuzzField(values=[80, 8080, 443], description="HTTP ports")) /
        Raw(load=b"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
    )

class BasicDNSCampaign(FuzzingCampaign):
    """Basic DNS fuzzing campaign."""
    name = "Basic DNS Fuzzing"
    target = "8.8.8.8"
    iterations = 5
    output_network = False
    output_pcap = "basic_dns.pcap"
    verbose = True
    
    packet = (
        IP(dst="8.8.8.8") /
        UDP(dport=53) /
        DNS(qd=DNSQR(qname=FuzzField(values=["example.com", "test.org", "fuzz.local"],
                                     description="Domain names")))
    )

class BasicTCPCampaign(FuzzingCampaign):
    """Basic TCP port scanning campaign."""
    name = "Basic TCP Port Scan"
    target = "192.168.1.100"
    iterations = 10
    output_network = False
    output_pcap = "basic_tcp.pcap"
    verbose = True
    
    packet = (
        IP(dst="192.168.1.100") /
        TCP(dport=FuzzField(values=list(range(1, 1025)), description="TCP ports"))
    )

# List of campaigns to run
campaigns = [
    BasicHTTPCampaign,
    BasicDNSCampaign,
    BasicTCPCampaign
]

def main():
    """Run all basic campaign examples."""
    print("=== Basic Campaign Examples ===")
    print()
    print("This example demonstrates:")
    print("1. Different types of campaigns (HTTP, DNS, TCP)")
    print("2. Using FuzzField with different value lists")
    print("3. Campaign configuration options")
    print()
    
    results = []
    
    for campaign_class in campaigns:
        campaign = campaign_class()
        print(f"\n--- Running {campaign.name} ---")
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"{campaign.name} completed successfully")
        else:
            print(f"{campaign.name} failed")
    
    print(f"\n=== Summary ===")
    print(f"Campaigns run: {len(campaigns)}")
    print(f"Successful: {sum(results)}")
    print(f"Failed: {len(results) - sum(results)}")
    
    return all(results)

if __name__ == "__main__":
    main()
