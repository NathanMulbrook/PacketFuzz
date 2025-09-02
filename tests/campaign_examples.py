"""
Enhanced campaign examples demonstrating field-level inclusion/exclusion patterns.
"""
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP, HTTPRequest  
from scapy.packet import Raw
from packetfuzz.fuzzing_framework import FuzzingCampaign

class MinimalTestCampaign(FuzzingCampaign):
    """Minimal campaign for testing purposes."""
    name = "MinimalTestCampaign"
    target = "127.0.0.1"
    packet = IP(dst="127.0.0.1")/TCP(dport=80)
    iterations = 1
    output_network = False

class LayerExclusionCampaign(FuzzingCampaign):
    """Example: Exclude specific layers from fuzzing."""
    name = "LayerExclusionExample"
    target = "127.0.0.1"
    packet = Ether()/IP(dst="127.0.0.1")/TCP(dport=80)/Raw(b"data")
    iterations = 5
    output_network = False
    
    # Exclude Raw and Ether layers completely
    excluded_layers = ["Raw", "Ether"]

class LayerWhitelistCampaign(FuzzingCampaign):
    """Example: Only fuzz specific layers (whitelist approach)."""
    name = "LayerWhitelistExample"
    target = "127.0.0.1"
    packet = Ether()/IP(dst="127.0.0.1")/TCP(dport=80)/Raw(b"data")
    iterations = 5
    output_network = False
    
    # Only fuzz TCP and IP layers, exclude all others
    layers_to_fuzz = ["TCP", "IP"]

class FieldExclusionCampaign(FuzzingCampaign):
    """Example: Exclude specific fields using pattern matching."""
    name = "FieldExclusionExample"
    target = "127.0.0.1"
    packet = IP(dst="127.0.0.1")/TCP(dport=80)/HTTP()/Raw(b"payload")
    iterations = 5
    output_network = False
    
    # Exclude destination ports from all layers and all IP version fields
    excluded_fields = [
        "*.dport",      # Exclude dport field from any layer
        "IP.version",   # Exclude version field from IP layer only
        "TCP.flags",    # Exclude TCP flags to avoid breaking connections
        "Raw.*"         # Exclude all fields from Raw layer
    ]

class FieldWhitelistCampaign(FuzzingCampaign):
    """Example: Only fuzz specific fields (whitelist approach)."""
    name = "FieldWhitelistExample"  
    target = "127.0.0.1"
    packet = IP(dst="127.0.0.1")/TCP(dport=80)/HTTP()/Raw(b"payload")
    iterations = 5
    output_network = False
    
    # Only fuzz these specific fields, exclude all others
    fields_to_fuzz = [
        "TCP.dport",    # Only fuzz TCP destination port
        "HTTP.*",       # Fuzz all HTTP fields
        "*.load"        # Fuzz load/payload fields in any layer
    ]

class MixedInclusionExclusionCampaign(FuzzingCampaign):
    """Example: Combine layer and field-level controls."""
    name = "MixedInclusionExclusionExample"
    target = "127.0.0.1"  
    packet = Ether()/IP(dst="127.0.0.1")/TCP(dport=80)/UDP(dport=53)/HTTP()
    iterations = 5
    output_network = False
    
    # Layer-level: Only fuzz TCP, IP, and HTTP layers
    layers_to_fuzz = ["TCP", "IP", "HTTP"]
    
    # Field-level: Even within allowed layers, exclude certain fields
    excluded_fields = [
        "IP.version",   # Don't fuzz IP version even though IP layer is allowed
        "TCP.flags",    # Don't fuzz TCP flags to maintain connection integrity
        "*.sport"       # Don't fuzz source ports from any layer
    ]

class AdvancedPatternCampaign(FuzzingCampaign):
    """Example: Advanced field pattern matching."""
    name = "AdvancedPatternExample"
    target = "127.0.0.1"
    packet = IP(dst="127.0.0.1")/TCP(dport=80, sport=12345)/UDP(dport=53, sport=54321)/Raw(b"data")
    iterations = 5
    output_network = False
    
    # Complex pattern matching examples
    excluded_fields = [
        # Exclude specific field combinations
        "TCP.sport",      # Exclude TCP source port specifically
        "UDP.dport",      # Exclude UDP destination port specifically  
        "*.version",      # Exclude version fields from all layers
        
        # Pattern examples (Layer.* means all fields in that layer)
        # "Raw.*" would exclude all Raw layer fields
    ]

# Example showing embedded field configuration alongside campaign-level controls
class EmbeddedConfigCampaign(FuzzingCampaign):
    """Example: Embedded field configuration with campaign-level controls."""
    name = "EmbeddedConfigExample"
    target = "127.0.0.1"
    iterations = 5
    output_network = False
    
    # Campaign-level exclusions
    excluded_fields = ["*.version", "TCP.flags"]
    
    def build_packets(self):
        packet = IP(dst="127.0.0.1")/TCP(dport=80)/Raw(b"test_data")
        
        # Embedded field-level configuration (highest priority)
        # This will override campaign-level settings
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        tcp_layer.field_fuzz('dport').fuzz_weight = 0.9  # High priority
        tcp_layer.field_fuzz('sport').fuzz_weight = 0.0  # Exclude (overrides campaign)
        
        return packet

CAMPAIGNS = [
    MinimalTestCampaign,
    LayerExclusionCampaign,
    LayerWhitelistCampaign,
    FieldExclusionCampaign,
    FieldWhitelistCampaign, 
    MixedInclusionExclusionCampaign,
    AdvancedPatternCampaign,
    EmbeddedConfigCampaign
]
