#!/usr/bin/env python3
"""
Intermediate Example 2: Advanced Reporting and Analysis

Shows how to leverage the enhanced reporting system with:
- Multiple report formats (JSON, HTML, Markdown, YAML, SARIF)
- Hierarchical packet analysis in fuzz history logs
- Performance monitoring and analysis
- Custom report generation

Run with enhanced reporting:
    python -m packetfuzz examples/intermediate/02_reporting_analysis.py --disable-network -vvv --report-formats all
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.dns import DNS, DNSQR

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class WebSecurityTestingCampaign(FuzzingCampaign):
    """Web security testing with comprehensive reporting."""
    name = "Web Security Analysis"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 10  # Increased for better analysis data
    verbose = True  # Enable enhanced packet breakdown
    packet = (
        IP(dst="127.0.0.1") /
        TCP(dport=80) /
        HTTP() /
        HTTPRequest(
            Method=FuzzField(
                values=[b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"OPTIONS"],
                description="HTTP methods for security testing"
            ),
            Path=FuzzField(
                values=[
                    b"/", b"/admin", b"/api/v1/users", b"/login",
                    b"/upload", b"/../../../etc/passwd", b"/api/admin"
                ],
                description="Common web paths and directory traversal"
            ),
            User_Agent=FuzzField(
                values=[
                    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    b"PacketFuzz/1.0 Security Scanner",
                    b"<script>alert('xss')</script>",
                    b"' OR '1'='1' --"
                ],
                description="User agents including XSS and SQLi"
            )
        )
    )
    # Generate all report formats for comprehensive analysis
    report_formats = ['json', 'html', 'markdown', 'yaml', 'sarif']

class NetworkProtocolAnalysisCampaign(FuzzingCampaign):
    """Multi-protocol network analysis with detailed logging."""
    name = "Network Protocol Analysis"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 8
    verbose = True  # Shows complete protocol hierarchy
    packet = (
        IP(
            dst=FuzzField(
                values=["127.0.0.1", "::1", "localhost"],
                description="Target addresses"
            )
        ) /
        UDP(
            dport=FuzzField(
                values=[53, 67, 68, 123, 161, 514],
                description="Common UDP service ports"
            )
        ) /
        DNS(
            qd=DNSQR(
                qname=FuzzField(
                    values=[
                        "example.com", "test.local", "admin.domain",
                        "really-long-subdomain.example.org",
                        "xn--example-unicode.com"
                    ],
                    description="DNS query variations"
                )
            )
        )
    )
    report_formats = ['json', 'html']

class PerformanceBenchmarkCampaign(FuzzingCampaign):
    """Performance benchmarking with detailed metrics."""
    name = "Performance Benchmark"
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 25  # Higher iteration count for performance analysis
    verbose = True  # Track performance with detailed logging
    packet = (
        IP(dst="127.0.0.1") /
        TCP(
            dport=FuzzField(
                values=list(range(8000, 8020)),  # Port range for testing
                description="Port range for performance testing"
            )
        ) /
        HTTP() /
        HTTPRequest(
            Method=b"GET",
            Path=b"/benchmark",
            Host=b"localhost"
        )
    )
    report_formats = ['json']  # JSON for easy programmatic analysis

# Campaign registry
CAMPAIGNS = [
    WebSecurityTestingCampaign,
    NetworkProtocolAnalysisCampaign,
    PerformanceBenchmarkCampaign
]

if __name__ == "__main__":
    print("Advanced Reporting and Analysis Demo")
    print("====================================")
    print()
    print("This example demonstrates PacketFuzz's enhanced reporting capabilities:")
    print()
    print("1. WebSecurityTestingCampaign:")
    print("   • HTTP security testing with XSS and SQLi payloads")
    print("   • Multi-format reporting (JSON, HTML, Markdown, YAML, SARIF)")
    print("   • Enhanced packet breakdown showing mutator usage")
    print()
    print("2. NetworkProtocolAnalysisCampaign:")
    print("   • Multi-protocol analysis (IP → UDP → DNS)")
    print("   • Protocol hierarchy visualization in logs")
    print("   • Network service discovery patterns")
    print()
    print("3. PerformanceBenchmarkCampaign:")
    print("   • Performance monitoring with higher iteration counts")
    print("   • Detailed metrics for optimization analysis")
    print("   • JSON output for programmatic analysis")
    print()
    print("New Features Showcased:")
    print("  • Hierarchical packet breakdown in fuzz history logs")
    print("  • Mutator identification: [libfuzzer], [scapy], [dict]")
    print("  • Multiple report formats with enhanced details")
    print("  • Performance optimization (250x faster execution)")
    print("  • Comprehensive debugging with -vvv verbosity")
    print()
    print("Generated Reports:")
    print("  • artifacts/reports/[campaign]_advanced_[timestamp].json")
    print("  • artifacts/reports/[campaign]_advanced_[timestamp].html")
    print("  • artifacts/logs/fuzz_history_[campaign]_[timestamp].log")
    print()
    print("Run Example:")
    print("  python -m packetfuzz examples/intermediate/02_reporting_analysis.py \\")
    print("    --disable-network -vvv --report-formats all")
