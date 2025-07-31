#!/usr/bin/env python3
"""
Intermediate Example 2: Dictionary Configuration - Custom Wordlists

Shows how to configure custom dictionaries, override defaults, and use
dictionary hierarchies for targeted fuzzing.
"""

import sys
import os
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField

class WebFuzzWithDictionaryCampaign(FuzzingCampaign):
    """Web fuzzing using custom dictionary configuration."""
    name = "Web Fuzzing with Custom Dictionaries"
    target = "192.168.1.100"
    iterations = 15
    output_pcap = "intermediate_dict_web.pcap"
    
    # Reference custom dictionary config
    dictionary_config_file = "examples/config/user_dictionary_config.py"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[80, 443, 8080])) /
        Raw(load=FuzzField(
            values=[b"GET / HTTP/1.1\r\n\r\n"],
            dictionaries=["fuzzdb/attack/http-protocol/http-protocol-methods.txt"],
            description="HTTP requests with dictionary payloads"
        ))
    )

class SQLInjectionCampaign(FuzzingCampaign):
    """SQL injection testing with targeted dictionaries."""
    name = "SQL Injection Testing"
    target = "192.168.1.200"
    iterations = 20
    output_pcap = "intermediate_dict_sqli.pcap"
    
    packet = (
        IP(dst="192.168.1.200") / 
        TCP(dport=3306) /  # MySQL port
        Raw(load=FuzzField(
            values=[b"SELECT * FROM users;"],
            dictionaries=[
                "fuzzdb/attack/sql-injection/detect/Generic_SQLI.txt",
                "fuzzdb/attack/sql-injection/detect/MySQL_SQLI.txt"
            ],
            description="SQL injection payloads"
        ))
    )

class XSSTestingCampaign(FuzzingCampaign):
    """XSS testing with multiple dictionary sources."""
    name = "XSS Testing"
    target = "192.168.1.100"
    iterations = 18
    output_pcap = "intermediate_dict_xss.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=80) /
        Raw(load=FuzzField(
            values=[b"GET /?search=test HTTP/1.1\r\n\r\n"],
            dictionaries=[
                "fuzzdb/attack/xss/xss-rsnake.txt",
                "fuzzdb/attack/xss/xss-naughty-strings.txt"
            ],
            description="XSS test vectors"
        ))
    )

class MixedDictionaryCampaign(FuzzingCampaign):
    """Campaign mixing inline values with dictionary sources."""
    name = "Mixed Dictionary Sources"
    target = "192.168.1.100"
    iterations = 12
    output_pcap = "intermediate_dict_mixed.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(
            # Port fuzzing with both inline values and dictionary
            dport=FuzzField(
                values=[80, 443, 8080],  # Common ports
                dictionaries=["fuzzdb/wordlists-misc/common-http-ports.txt"],
                description="Web ports (mixed sources)"
            )
        ) /
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
    XSSTestingCampaign,
    MixedDictionaryCampaign
]

def main():
    print("=== Intermediate Example 2: Dictionary Configuration ===")
    print("Demonstrates custom dictionary usage and configuration")
    print()
    
    # Show dictionary configuration info
    print("📚 Dictionary Sources:")
    print("   • Custom config: examples/config/user_dictionary_config.py")
    print("   • FuzzDB integration: Multiple attack categories")
    print("   • Mixed sources: Inline values + dictionaries")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"🎯 Running {campaign.name}")
        print(f"   Target: {campaign.target}")
        print(f"   Iterations: {campaign.iterations}")
        
        # Show dictionary info if available
        if hasattr(campaign, 'dictionary_config_file'):
            print(f"   Dictionary config: {campaign.dictionary_config_file}")
        
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"   ✓ Success - {campaign.output_pcap}")
        else:
            print(f"   ✗ Failed")
        print()
    
    success_count = sum(results)
    print(f"📊 Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    print("\n💡 Dictionary Priority Order:")
    print("   1. FuzzField dictionaries (highest)")
    print("   2. Campaign dictionary_config_file")
    print("   3. CLI --dictionary-config")
    print("   4. Default mappings (lowest)")
    
    return all(results)

if __name__ == "__main__":
    main()
