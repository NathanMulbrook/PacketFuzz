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
from scapy.layers.http import HTTP, HTTPRequest
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
        IP() /
        TCP() /
        HTTP() /
        HTTPRequest(Path=b"/", Method=b"GET", Host=b"target.com")
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
        IP() /
        UDP() /
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
        IP() /
        TCP()
    )

class MalformedPacketCampaign(FuzzingCampaign):
    """Malformed packet campaign with interface offload management."""
    name = "Malformed Packet Test"
    target = "192.168.1.100"
    iterations = 5
    output_network = False  # Keep disabled for safety in examples
    output_pcap = "malformed_packets.pcap"
    verbose = True
    
    # Enable interface offload management for malformed packets
    # (Only takes effect when output_network=True and running as root)
    disable_interface_offload = True
    interface = "eth0"
    
    packet = (
        IP() /
        TCP(
            window=FuzzField(values=[0, 1, 65535], description="Edge case TCP windows")
        ) /
        HTTP() /
        HTTPRequest(Path=b"/", Method=b"GET")
    )

# List of campaigns to run
campaigns = [
    BasicHTTPCampaign,
    BasicDNSCampaign,
    BasicTCPCampaign,
    MalformedPacketCampaign
]
