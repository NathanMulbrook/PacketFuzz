#!/usr/bin/env python3
"""
Advanced Campaign Patterns

Demonstrates advanced campaign features:
- Advanced field mapping overrides (complex field filtering)
- Excluded fields and layers  
- Custom mutator preferences per field type
- Advanced callback chaining

Run with: python -m packetfuzz examples/advanced/01_advanced_patterns.py --disable-network
"""

import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR  
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class AdvancedFieldMappingCampaign(FuzzingCampaign):
    """Advanced field mapping overrides for precise fuzzing control."""
    name = "Advanced Field Mapping"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 10
    output_network = False
    verbose = True
    
    # Advanced field mapping overrides - complex field filtering
    advanced_field_mapping_overrides = [
        # Heavily fuzz HTTP request fields
        {"layer": "HTTPRequest", "field": "Path", "fuzz_weight": 1.0},
        {"layer": "HTTPRequest", "field": "User_Agent", "fuzz_weight": 0.8},
        
        # Lightly fuzz network layer
        {"layer": "IP", "field": "dst", "fuzz_weight": 0.2}, 
        {"layer": "TCP", "field": "dport", "fuzz_weight": 0.3},
        
        # Don't fuzz certain fields at all
        {"layer": "IP", "field": "src", "fuzz_weight": 0.0},
        {"layer": "TCP", "field": "sport", "fuzz_weight": 0.0}
    ]
    
    packet = (
        IP(src="10.0.0.1", dst="127.0.0.1") /
        TCP(sport=12345, dport=80) /
        HTTP() /
        HTTPRequest(
            Path=b"/api/v1/users", 
            Method=b"POST",
            User_Agent=b"TestClient/1.0"
        )
    )

class ExclusionFilteringCampaign(FuzzingCampaign):
    """Demonstrate excluded_fields and excluded_layers filtering.""" 
    name = "Exclusion Filtering"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 8
    output_network = False
    verbose = True
    
    # Exclude specific fields from fuzzing
    excluded_fields = ["src", "sport", "version", "ihl"]  
    # This will fuzz everything EXCEPT these fields
    
    packet = (
        IP(src="192.168.1.100", dst="127.0.0.1") /
        TCP(sport=54321, dport=80) /
        HTTP() /
        HTTPRequest(Path=b"/admin", Method=b"GET")
    )

class LayerExclusionCampaign(FuzzingCampaign):
    """Demonstrate excluded_layers for layer-level filtering."""
    name = "Layer Exclusion"
    socket_config = RawIPConfig(target="127.0.0.1") 
    iterations = 8
    output_network = False
    verbose = True
    
    # Exclude entire layers from fuzzing
    excluded_layers = ["IP", "TCP"]  # Only fuzz HTTP layer
    
    packet = (
        IP(dst="127.0.0.1") /
        TCP(dport=80) /
        HTTP() /
        HTTPRequest(
            Path=b"/search",
            Method=b"POST", 
            Host=b"example.com",
            User_Agent=b"SearchBot/2.0"
        )
    )

def advanced_pre_send_callback(context, packet):
    """Advanced callback with state tracking."""
    # Track packet modifications across iterations
    if not hasattr(context.campaign, '_packet_mods'):
        context.campaign._packet_mods = {}
    
    # Apply dynamic modifications based on iteration
    iteration = context.campaign.context.iteration if hasattr(context.campaign.context, 'iteration') else 0
    
    if iteration % 3 == 0 and HTTP in packet:
        # Every 3rd packet, add custom header
        if HTTPRequest in packet:
            print(f"Iteration {iteration}: Adding X-Fuzz header")
            context.campaign._packet_mods[iteration] = "added_header"
    
    return CallbackResult.SUCCESS

def advanced_post_send_callback(context, packet, response=None):
    """Advanced post-send analysis."""
    iteration = context.campaign.context.iteration if hasattr(context.campaign.context, 'iteration') else 0
    
    if hasattr(context.campaign, '_packet_mods') and iteration in context.campaign._packet_mods:
        mod_type = context.campaign._packet_mods[iteration]
        print(f"Iteration {iteration}: Sent packet with {mod_type}")
    
    return CallbackResult.SUCCESS

class ChainedCallbacksCampaign(FuzzingCampaign):
    """Demonstrate multiple callback chaining."""
    name = "Chained Callbacks"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 6
    output_network = False
    verbose = True
    
    # Multiple callbacks for comprehensive monitoring
    pre_send_callback = advanced_pre_send_callback
    post_send_callback = advanced_post_send_callback
    
    packet = (
        IP() /
        TCP(dport=443) /
        HTTP() /
        HTTPRequest(Path=b"/secure/api", Method=b"POST")
    )

# Register campaigns for CLI discovery
CAMPAIGNS = [
    AdvancedFieldMappingCampaign,
    ExclusionFilteringCampaign,
    LayerExclusionCampaign,
    ChainedCallbacksCampaign
]

if __name__ == "__main__":
    print("Running advanced campaign pattern examples...")
    
    for campaign_class in CAMPAIGNS:
        print(f"\n=== {campaign_class.__name__} ===")
        campaign_class().execute()
