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

def demonstrate_mutator_weights():
    """Show how mutator weights work in practice."""
    
    print("=== Weighted Mutator Selection Demo ===\n")
    
    print("1. FuzzField Mutator Weight Examples:")
    
    # Example 1: Dict format
    ff1 = FuzzField(mutators={"libfuzzer": 0.7, "scapy": 0.3})
    print(f"   Dict format: {ff1.mutators}")
    
    # Example 2: List format (auto-converted)
    ff2 = FuzzField(mutators=["libfuzzer", "dictionary_only", "scapy"])
    print(f"   List format (converted): {ff2.mutators}")
    
    # Example 3: Default (None)
    ff3 = FuzzField()
    print(f"   Default (None): {ff3.mutators}")
    
    print("\n2. Campaign Mutator Weight Examples:")
    
    # HTTP campaign with weighted preferences
    http_campaign = HTTPWeightedMutatorCampaign()
    print(f"   HTTP Campaign: {http_campaign.mutator_preference}")
    
    # TCP campaign with list (auto-converted)
    tcp_campaign = TCPPortScanCampaign()
    print(f"   TCP Campaign: {tcp_campaign.mutator_preference}")
    
    print("\n3. Priority Order:")
    print("   1. FuzzField mutator weights (highest priority)")
    print("   2. Default mappings (field type/name based)")
    print("   3. Campaign mutator_preference")
    print("   4. Global default ({\"libfuzzer\": 1.0})")

def run_example_campaigns():
    """Run the example campaigns to show weighted selection in action."""
    
    print("\n=== Running Example Campaigns ===\n")
    
    print("🌐 Running HTTP Weighted Mutator Campaign...")
    http_campaign = HTTPWeightedMutatorCampaign()
    try:
        result = http_campaign.execute()
        print(f"   ✓ HTTP Campaign completed: {result}")
    except Exception as e:
        print(f"   ⚠ HTTP Campaign failed: {e}")
    
    print("\n🔍 Running TCP Port Scan with Default Weights...")
    tcp_campaign = TCPPortScanCampaign()
    try:
        result = tcp_campaign.execute()
        print(f"   ✓ TCP Campaign completed: {result}")
    except Exception as e:
        print(f"   ⚠ TCP Campaign failed: {e}")

if __name__ == "__main__":
    demonstrate_mutator_weights()
    run_example_campaigns()
    print("\n✅ Demo completed! Check the logs above to see weighted mutator selection in action.")
