#!/usr/bin/env python3
"""
Basic Example 3: Enhanced Debugging Features

This example demonstrates the new enhanced debugging and logging features:
- Hierarchical packet breakdown showing all protocol layers
- Mutator identification for each fuzzed field
- Verbose logging levels for detailed analysis
- Performance-optimized execution

Run with different verbosity levels to see the enhanced output:
    python -m packetfuzz examples/basic/03_enhanced_debugging.py --disable-network -v
    python -m packetfuzz examples/basic/03_enhanced_debugging.py --disable-network -vv
    python -m packetfuzz examples/basic/03_enhanced_debugging.py --disable-network -vvv
"""

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class HTTPDebuggingCampaign(FuzzingCampaign):
    """HTTP fuzzing with enhanced debugging output."""
    name = "HTTP Debug Demo"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 3
    verbose = True  # Enable enhanced packet breakdown
    packet = (
        IP(dst="127.0.0.1") /
        TCP(dport=80, sport=12345) /
        HTTP() /
        HTTPRequest(
            Method=b"POST",
            Path=b"/api/submit",
            Host=b"example.com",
            User_Agent=b"PacketFuzz/1.0",
            Content_Type=b"application/json"
        )
    )
    report_formats = ['json', 'html']

class MultiProtocolDebuggingCampaign(FuzzingCampaign):
    """Multi-protocol fuzzing showing hierarchical breakdown."""
    name = "Multi-Protocol Debug"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 2
    verbose = True  # Shows complete protocol hierarchy
    packet = (
        IP(dst="127.0.0.1", src="10.0.0.1") /
        UDP(dport=53, sport=54321) /
        DNS(
            qd=DNSQR(
                qname=FuzzField(
                    values=["example.com", "test.local", "fuzz.domain"],
                    description="DNS query targets"
                )
            )
        )
    )
    report_formats = ['json']

class FuzzFieldDebuggingCampaign(FuzzingCampaign):
    """Targeted field fuzzing with mutator identification."""
    name = "FuzzField Debug Demo"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 4
    verbose = True  # Shows which mutators were used for each field
    packet = (
        IP(dst="127.0.0.1") /
        TCP(
            dport=FuzzField(
                values=[80, 443, 8080, 3000],
                description="Web server ports"
            )
        ) /
        HTTP() /
        HTTPRequest(
            Method=FuzzField(
                values=[b"GET", b"POST", b"PUT", b"DELETE"],
                description="HTTP methods"
            ),
            Path=FuzzField(
                values=[b"/", b"/admin", b"/api/v1", b"/test"],
                description="URL paths"
            )
        )
    )
    report_formats = ['json', 'html']

# Register campaigns for CLI discovery
CAMPAIGNS = [HTTPDebuggingCampaign, MultiProtocolDebuggingCampaign, FuzzFieldDebuggingCampaign]

if __name__ == "__main__":
    print("Enhanced Debugging Features Demo")
    print("================================")
    print()
    print("This example showcases PacketFuzz's enhanced debugging capabilities:")
    print()
    print("1. HTTPDebuggingCampaign:")
    print("   • HTTP packet fuzzing with complete field breakdown")
    print("   • Shows IP → TCP → HTTP → HTTPRequest hierarchy")
    print()
    print("2. MultiProtocolDebuggingCampaign:")
    print("   • DNS over UDP fuzzing")
    print("   • Demonstrates IP → UDP → DNS packet structure")
    print()
    print("3. FuzzFieldDebuggingCampaign:")
    print("   • Targeted field fuzzing with custom values")
    print("   • Shows which mutator (LibFuzz, Scapy, Dict) was used")
    print()
    print("Key Features Demonstrated:")
    print("  • Hierarchical packet breakdown in fuzz history logs")
    print("  • Mutator identification: [libfuzzer], [scapy], [dict]")
    print("  • Enhanced verbose logging with -v, -vv, -vvv")
    print("  • Performance-optimized execution")
    print("  • Multiple report formats")
    print()
    print("Try different verbosity levels:")
    print("  -v   : Basic campaign information")
    print("  -vv  : Detailed packet information")
    print("  -vvv : Complete packet breakdown with mutator details")
