#!/usr/bin/env python3
"""
Intermediate Example 1: Campaign Inheritance - Reusable Configurations

Shows how to use campaign inheritance to create reusable base configurations
and specialized campaigns.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class WebAppBaseCampaign(FuzzingCampaign):
    """Base campaign for web application testing."""
    target = "192.168.1.100"
    rate_limit = 10.0
    output_network = False
    verbose = True
    
    # Common web application packet structure
    def get_base_packet(self):
        return IP(dst=self.target) / TCP()

class HTTPFuzzCampaign(WebAppBaseCampaign):
    """HTTP-specific fuzzing campaign."""
    name = "HTTP Fuzzing"
    iterations = 3  # Reduced for faster execution in tests
    output_pcap = "intermediate_http_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[80, 8080, 8000])) /
        Raw(load=FuzzField(values=[
            b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n",
            b"GET /admin HTTP/1.1\r\nHost: test.com\r\n\r\n",
            b"POST /login HTTP/1.1\r\nHost: test.com\r\nContent-Length: 0\r\n\r\n"
        ]))
    )

class HTTPSFuzzCampaign(WebAppBaseCampaign):
    """HTTPS-specific fuzzing campaign."""
    name = "HTTPS Fuzzing"
    iterations = 2  # Reduced for faster execution in tests
    output_pcap = "intermediate_https_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[443, 8443, 9443])) /
        Raw(load=FuzzField(values=[
            b"TLS handshake data",
            b"Encrypted HTTP data",
            b"Certificate data"
        ]))
    )

class APIFuzzCampaign(WebAppBaseCampaign):
    """API-specific fuzzing campaign."""
    name = "API Fuzzing" 
    iterations = 3  # Reduced for faster execution in tests
    output_pcap = "intermediate_api_fuzz.pcap"
    rate_limit = 5.0  # Slower for API testing
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[3000, 8000, 8080])) /
        Raw(load=FuzzField(values=[
            b'{"api_key": "test", "action": "get"}',
            b'{"api_key": "admin", "action": "delete"}',
            b'{"api_key": "' + b'A' * 1000 + b'", "action": "overflow"}'
        ]))
    )

# Different base for network infrastructure
class NetworkBaseCampaign(FuzzingCampaign):
    """Base campaign for network infrastructure testing."""
    rate_limit = 20.0
    output_network = False
    verbose = True

class DNSFuzzCampaign(NetworkBaseCampaign):
    """DNS-specific fuzzing campaign."""
    name = "DNS Fuzzing"
    target = "8.8.8.8"
    iterations = 2  # Reduced for faster execution in tests
    output_pcap = "intermediate_dns_fuzz.pcap"
    
    packet = (
        IP(dst="8.8.8.8") / 
        UDP(dport=53) / 
        DNS(qd=DNSQR(qname=FuzzField(values=[
            "example.com",
            "test.org", 
            "a" * 63 + ".com",  # Max label length
            "overflow." + "a" * 200 + ".com"  # Overflow test
        ])))
    )

# Campaign registry
CAMPAIGNS = [
    HTTPFuzzCampaign,
    HTTPSFuzzCampaign,
    APIFuzzCampaign,
    DNSFuzzCampaign
]

def main():
    print("=== Intermediate Example 1: Campaign Inheritance ===")
    print("Demonstrates reusable base campaigns and specialization")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"🚀 Running {campaign.name}")
        print(f"   Target: {campaign.target}")
        print(f"   Rate limit: {campaign.rate_limit} pps")
        print(f"   Iterations: {campaign.iterations}")
        
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"   ✓ Success - {campaign.output_pcap}")
        else:
            print(f"   ✗ Failed")
        print()
    
    success_count = sum(results)
    print(f"📊 Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    # Show inheritance hierarchy
    print("\n📋 Campaign Inheritance:")
    print("   WebAppBaseCampaign")
    print("   ├── HTTPFuzzCampaign")
    print("   ├── HTTPSFuzzCampaign")
    print("   └── APIFuzzCampaign")
    print("   NetworkBaseCampaign")
    print("   └── DNSFuzzCampaign")
    
    return all(results)

if __name__ == "__main__":
    main()
