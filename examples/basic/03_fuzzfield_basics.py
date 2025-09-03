#!/usr/bin/env python3
"""
Basic FuzzField examples showing how to define fields with specific values.

This example demonstrates the fundamental usage of FuzzField for targeted
field-level fuzzing with predefined value sets.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class BasicFuzzFieldCampaign(FuzzingCampaign):
    """Simple FuzzField demonstration."""
    name = "Basic FuzzField Demo"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 3
    output_network = False
    output_pcap = "basic_fuzzfield.pcap"
    verbose = True
    
    packet = (
        IP() /
        TCP(
            dport=FuzzField(
                values=[80, 443, 8080],
                description="Common web ports"
            )
        ) /
        Raw(
            load=FuzzField(
                values=[b"Hello", b"World", b"Test"],
                description="Simple payloads"
            )
        )
    )

class DNSFuzzFieldCampaign(FuzzingCampaign):
    """DNS query fuzzing with FuzzField."""
    name = "DNS FuzzField Demo"
    socket_config = RawIPConfig(target="8.8.8.8")
    iterations = 2
    output_network = False
    output_pcap = "dns_fuzzfield.pcap"
    verbose = True
    
    packet = (
        IP() /
        UDP(dport=53) /
        DNS(
            qd=DNSQR(
                qname=FuzzField(
                    values=["example.com", "test.org"],
                    description="Test domains"
                )
            )
        )
    )

if __name__ == "__main__":
    print("Running basic FuzzField examples...")
    
    print("\n=== Basic FuzzField Campaign ===")
    BasicFuzzFieldCampaign().execute()
    
    print("\n=== DNS FuzzField Campaign ===")
    DNSFuzzFieldCampaign().execute()

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.layers.http import HTTP, HTTPRequest
  

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class IntegerFuzzCampaign(FuzzingCampaign):
    """Demonstrates integer field fuzzing."""
    name = "Integer Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 5
    output_pcap = "basic_integer_fuzz.pcap"
    
    packet = (
        IP() / 
        TCP()
    )

class StringFuzzCampaign(FuzzingCampaign):
    """Demonstrates string field fuzzing."""
    name = "String Fuzzing"
    socket_config = RawIPConfig(target="10.10.10.10")
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
    socket_config = RawIPConfig(target="192.168.1.100")
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
