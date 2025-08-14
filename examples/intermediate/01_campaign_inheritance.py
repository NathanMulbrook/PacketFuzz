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
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

# This shows how inheritance can be set to make small changes to a base campaign
class DNSBaseCampaign(FuzzingCampaign):
    """Base campaign for network infrastructure testing."""
    rate_limit = 10.0
    output_network = False
    verbose = False
    iterations = 1
    packet = (
        IP() / 
        UDP() / 
        DNS()
    )

class DNSTarget1(DNSBaseCampaign):
    """DNS-specific fuzzing campaign."""
    name = "DNS Fuzzing 1"
    target = "10.0.0.1"
    output_pcap = "intermediate_dns_fuzz_1.pcap"

class DNSTarget2(DNSBaseCampaign):
    """DNS-specific fuzzing campaign."""
    name = "DNS Fuzzing 2"
    target = "10.0.0.2"
    output_pcap = "intermediate_dns_fuzz_2.pcap"
    


# THis shows more advanced inheritance for sending different data
HTTPBasePacket = (IP() / 
                TCP() /
                HTTP()
                )
class WebAppBaseCampaign(FuzzingCampaign):
    """Base campaign for web application testing."""
    target = "192.168.1.100"
    rate_limit = 10.0
    iterations = 1  # Reduced for faster execution in tests
    output_network = False
    verbose = False


class HTTPFuzzCampaign(WebAppBaseCampaign):
    """HTTP-specific fuzzing campaign."""
    name = "HTTP Fuzzing"
    output_pcap = "intermediate_http_request_fuzz.pcap"
    packet = (
        HTTPBasePacket /
        HTTPRequest()
    )

class HTTPSFuzzCampaign(WebAppBaseCampaign):
    """HTTPS-specific fuzzing campaign."""
    name = "HTTPS Fuzzing"
    output_pcap = "intermediate_http_response_fuzz.pcap"    
    packet = (
        HTTPBasePacket /
        HTTPResponse()
    )

class APIFuzzCampaign(WebAppBaseCampaign):
    """API-specific fuzzing campaign."""
    name = "API Fuzzing" 
    iterations = 1  # Reduced for faster execution in tests
    output_pcap = "intermediate_api_fuzz.pcap"
    rate_limit = 5.0  # Slower for API testing
    
    packet = (HTTPBasePacket /
        HTTPRequest() / 
        Raw(load=FuzzField(values=[
            b'{"api_key": "test", "action": "get"}',
            b'{"api_key": "admin", "action": "delete"}',
            b'{"api_key": "' + b'A' * 1000 + b'", "action": "overflow"}'
        ]))
    )


# Campaign registry
CAMPAIGNS = [
    DNSTarget1,
    DNSTarget2,
    HTTPFuzzCampaign,
    HTTPSFuzzCampaign,
    APIFuzzCampaign,
]
