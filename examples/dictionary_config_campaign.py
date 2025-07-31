#!/usr/bin/env python3
"""
Dictionary Configuration Campaign Examples

This file contains example campaigns that demonstrate dictionary configuration functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fuzzing_framework import FuzzingCampaign
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


class BasicDictionaryConfigCampaign(FuzzingCampaign):
    """Basic campaign with dictionary configuration"""
    
    name = "Basic Dictionary Config"
    description = "Example campaign with basic dictionary configuration"
    target = "192.168.1.100"
    dictionary_config_file = "examples/user_dictionary_config.py"
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst=self.target)/TCP(dport=80)
        
    def build_packets(self):
        """Build test packets"""
        return [self.packet]


class AdvancedDictionaryConfigCampaign(FuzzingCampaign):
    """Advanced campaign with inline dictionary configuration"""
    
    name = "Advanced Dictionary Config"
    description = "Example campaign with inline field configuration"
    target = "192.168.1.100"
    
    def __init__(self):
        super().__init__()
        self.packet = IP(dst=self.target)/TCP(dport=80)/Raw(load=b"test")
        
    def build_packets(self):
        """Build test packets with inline configuration"""
        packet = IP(dst=self.target)/TCP(dport=80)/Raw(load=b"test")
        
        # Configure inline field fuzzing
        packet[TCP].field_fuzz('dport').dictionary = ["custom_ports.txt"]
        packet[TCP].field_fuzz('dport').fuzz_weight = 0.75
        packet[Raw].field_fuzz('load').dictionary = ["payloads.txt"]
        
        return [packet]


# Campaign registry for CLI
CAMPAIGNS = [
    BasicDictionaryConfigCampaign,
    AdvancedDictionaryConfigCampaign
]
