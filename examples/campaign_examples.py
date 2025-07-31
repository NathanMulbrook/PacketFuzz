#!/usr/bin/env python3
"""
Campaign Examples - Standard Campaign Configurations

This file demonstrates various campaign patterns and configurations
for the Scapy Fuzzing Framework.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fuzzing_framework import FuzzingCampaign, FuzzField


class WebAppFuzzCampaign(FuzzingCampaign):
    """Web application fuzzing campaign"""
    name = "Web Application Fuzzing"
    target = "192.168.1.100"
    iterations = 100
    rate_limit = 20.0
    output_network = False
    output_pcap = "webapp_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[80, 443, 8080, 8443, 3000], description="Web server ports")) /
        Raw(load=FuzzField(values=[b"GET / HTTP/1.1\r\n\r\n", 
                                  b"GET /admin HTTP/1.1\r\n\r\n",
                                  b"POST /login HTTP/1.1\r\n\r\n"],
                          description="HTTP requests"))
    )


class DNSInfrastructureFuzzCampaign(FuzzingCampaign):
    """DNS infrastructure fuzzing campaign"""
    name = "DNS Infrastructure Fuzzing"
    target = "8.8.8.8"
    iterations = 50
    rate_limit = 5.0
    output_network = False
    output_pcap = "dns_infrastructure_fuzz.pcap"
    
    packet = (
        IP(dst="8.8.8.8") /
        UDP(dport=53) /
        DNS(qd=DNSQR(qname=FuzzField(values=["example.com", "test.local", "fuzz.domain"],
                                   description="Domain names")))
    )


class NetworkConnectivityFuzzCampaign(FuzzingCampaign):
    """Network connectivity fuzzing campaign"""
    name = "Network Connectivity Fuzzing"
    target = "192.168.1.1"
    iterations = 25
    rate_limit = 10.0
    output_network = False
    output_pcap = "network_connectivity_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.1") /
        TCP(dport=FuzzField(values=list(range(1, 1025)), description="TCP ports"))
    )


# Campaign registry for framework execution
CAMPAIGNS = [
    WebAppFuzzCampaign,
    DNSInfrastructureFuzzCampaign,
    NetworkConnectivityFuzzCampaign
]


if __name__ == "__main__":
    print("=== Campaign Examples ===")
    print()
    print("Available campaigns:")
    for i, campaign_class in enumerate(CAMPAIGNS, 1):
        campaign = campaign_class()
        print(f"{i}. {campaign.name}")
        print(f"   Target: {campaign.target}")
        print(f"   Iterations: {campaign.iterations}")
        print(f"   Output: {campaign.output_pcap}")
        print()
    
    print("Usage:")
    print("  scapy-fuzzer examples/campaign_examples.py")
    print("  scapy-fuzzer examples/campaign_examples.py --list-campaigns")
    print("  scapy-fuzzer examples/campaign_examples.py --dry-run")
