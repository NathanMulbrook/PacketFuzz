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
from scapy.layers.http import HTTP, HTTPRequest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class IntegerFuzzCampaign(FuzzingCampaign):
    """Demonstrates integer field fuzzing."""
    name = "Integer Fuzzing"
    target = "192.168.1.100"
    iterations = 5
    output_pcap = "basic_integer_fuzz.pcap"
    
    packet = (
        IP() / 
        TCP()
    )

class StringFuzzCampaign(FuzzingCampaign):
    """Demonstrates string field fuzzing."""
    name = "String Fuzzing"
    target = "10.10.10.10"
    iterations = 5
    output_pcap = "basic_string_fuzz.pcap"
    
    packet = (
        IP() / 
        UDP() / 
        DNS(qd=DNSQR(qname=FuzzField(values=["example.com", "test.org", "fuzz.local"])))
    )

class BytesFuzzCampaign(FuzzingCampaign):
    """Demonstrates bytes/payload fuzzing."""
    name = "Bytes Fuzzing"
    target = "192.168.1.100"
    iterations = 5
    output_pcap = "basic_bytes_fuzz.pcap"
    
    packet = (
        IP() / 
        TCP() / 
        HTTP() /
        HTTPRequest(
            Path=FuzzField(values=[b"/", b"/api", b"/data"]),
            Method=FuzzField(values=[b"GET", b"POST", b"PUT"])
        )
    )

# Campaign list for easy execution
CAMPAIGNS = [
    IntegerFuzzCampaign,
    StringFuzzCampaign,
    BytesFuzzCampaign
]
