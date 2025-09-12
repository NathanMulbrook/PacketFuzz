#!/usr/bin/env python3
"""
Example demonstrating weighted mutator selection in PacketFuzz.

This example shows how to use the new weighted mutator selection feature
to control the probability of different mutators being used for fuzzing.
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest
from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class HTTPWeightedMutatorCampaign(FuzzingCampaign):
    """
    Demonstrates weighted mutator selection for HTTP fuzzing.
    
    Features:
    - Campaign-level mutator weights favoring dictionary attacks
    - Field-level overrides for specific fields
    - Mixing dict and list formats for compatibility
    """
    name = "HTTP Weighted Mutator Example"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 10
    output_network = False
    verbose = True
    
    # Campaign-level weighted mutator preferences
    # This will be the default for all fields unless overridden
    mutator_preference = {
        "dictionary_only": 0.6,  # 60% chance for dictionary-only attacks
        "libfuzzer": 0.3,        # 30% chance for libfuzzer mutations  
        "scapy": 0.1             # 10% chance for scapy mutations
    }
    
    packet = (
        IP() /
        TCP(dport=80) /
        HTTP() /
        HTTPRequest(
            # User-Agent: heavily favor dictionary attacks (common attack vector)
            User_Agent=FuzzField(
                dictionaries=["fuzzdb/attack/http-protocol/user-agents.txt"],
                mutators={"dictionary_only": 0.9, "libfuzzer": 0.1}
            ),
            
            # Path: balanced approach for path traversal and injection
            Path=FuzzField(
                values=[b"/", b"/admin", b"/api"],
                mutators={"dictionary_only": 0.5, "libfuzzer": 0.5}
            ),
            
            # Method: mostly stick to valid HTTP methods  
            Method=FuzzField(
                values=[b"GET", b"POST", b"PUT", b"DELETE"],
                mutators={"dictionary_only": 0.8, "scapy": 0.2}
            ),
            
            # Host: Legacy list format (will be auto-converted to equal weights)
            Host=FuzzField(
                values=[b"localhost", b"example.com"],
                mutators=["dictionary_only", "libfuzzer"]  # Equal weights (0.5 each)
            )
        )
    )

class TCPPortScanCampaign(FuzzingCampaign):
    """
    Demonstrates using default mappings for mutator selection.
    
    No explicit mutator weights specified - will use defaults from
    default_mappings.py based on field types and names.
    """
    name = "TCP Port Scan with Default Weights"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 5
    output_network = False
    
    # Campaign uses list format (will be normalized to dict)
    mutator_preference = ["libfuzzer", "dictionary_only"]
    
    packet = (
        IP() /
        TCP()  # Will use default mutator weights from mappings
    )

CAMPAIGNS = [HTTPWeightedMutatorCampaign, TCPPortScanCampaign]  
