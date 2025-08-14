#!/usr/bin/env python3
"""
Intermediate Example 2: Dictionary Configuration - Custom Wordlists

Shows how to configure custom dictionaries, override defaults, and use
dictionary hierarchies for targeted fuzzing.
"""

import sys
import os
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

HTTPBasePacket = (IP() /
                  TCP(dport=FuzzField(values=[80, 443, 8080])) /
                  HTTP())
class WebFuzzWithDictionaryCampaign(FuzzingCampaign):
    """Web fuzzing using custom dictionary configuration."""
    name = "Web Fuzzing with Custom Dictionaries"
    target = "192.168.1.100"
    iterations = 1
    output_pcap = "intermediate_dict_web.pcap"
    verbose = False
    capture_responses = False
    output_network = False
    rate_limit = None
    
    # Reference custom dictionary config
    dictionary_config_file = "examples/config/user_dictionary_config.py"
    
    packet = (
        HTTPBasePacket /
        HTTPRequest() /
        Raw(load=FuzzField(
            dictionaries=["fuzzdb/attack/http-protocol/http-protocol-methods.txt"],
            description="HTTP requests with dictionary payloads"
        ))
    )

class SQLInjectionCampaign(FuzzingCampaign):
    """SQL injection testing with targeted dictionaries."""
    name = "SQL Injection Testing"
    target = "192.168.1.200"
    iterations = 1
    output_pcap = "intermediate_dict_sqli.pcap"
    verbose = False
    capture_responses = False
    output_network = False
    rate_limit = None
    
    packet = (
        IP() /
        TCP() /  # MySQL port set by framework/callback
        Raw(load=FuzzField(
            values=[b"SELECT * FROM users;"],
            dictionaries=[
                "fuzzdb/attack/sql-injection/detect/Generic_SQLI.txt",
                "fuzzdb/attack/sql-injection/detect/MySQL_SQLI.txt"
            ],
            description="SQL injection payloads"
        ))
    )

class MixedDictionaryCampaign(FuzzingCampaign):
    """Campaign mixing inline values with dictionary sources."""
    name = "Mixed Dictionary Sources"
    target = "192.168.1.100"
    iterations = 1
    output_pcap = "intermediate_dict_mixed.pcap"
    verbose = False
    capture_responses = False
    output_network = False
    rate_limit = None
    
    packet = (
        IP() / 
        TCP() /
        Raw(load=FuzzField(
            values=[
                b"GET / HTTP/1.1\r\n\r\n",
                b"POST / HTTP/1.1\r\n\r\n"
            ],
            dictionaries=["fuzzdb/attack/http-protocol/http-protocol-methods.txt"],
            description="HTTP methods (mixed sources)"
        ))
    )

# Campaign registry
CAMPAIGNS = [
    WebFuzzWithDictionaryCampaign,
    SQLInjectionCampaign,
    MixedDictionaryCampaign
]
