#!/usr/bin/env python3
"""
Report Generation Examples

This example demonstrates the various report generation capabilities in PacketFuzz.
Shows how to configure different report formats for different use cases.
"""

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR


class HTMLReportCampaign(FuzzingCampaign):
    """Campaign that generates HTML reports for human-readable analysis"""
    
    def __init__(self):
        super().__init__()
        self.name = "HTML Report Demo"
        self.target = "192.168.1.100"
        self.iterations = 20
        
        # Generate HTML report for human review
        self.report_formats = ['html']
        
        # Disable network output for demo
        self.output_network = False
        self.output_pcap = "html_demo.pcap"
        
    def build_packets(self):
        return [
            IP(dst=self.target) / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
            IP(dst=self.target) / TCP(dport=443) / Raw(load=b"HTTPS test"),
        ]


class SecurityAnalysisCampaign(FuzzingCampaign):
    """Campaign that generates SARIF reports for security tool integration"""
    
    def __init__(self):
        super().__init__()
        self.name = "Security Analysis Demo"
        self.target = "192.168.1.100"
        self.iterations = 30
        
        # Generate SARIF format for security tools (plus HTML for human review)
        self.report_formats = ['sarif', 'html']
        
        self.output_network = False
        self.output_pcap = "security_demo.pcap"
        self.verbose = True
        
    def build_packets(self):
        return [
            IP(dst=self.target) / TCP(dport=80) / Raw(load=b"GET /../../../etc/passwd HTTP/1.1\r\n\r\n"),
            IP(dst=self.target) / TCP(dport=80) / Raw(load=b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
            IP(dst=self.target) / TCP(dport=22) / Raw(load=b"SSH-2.0-OpenSSH_8.0"),
        ]


class PerformanceAnalysisCampaign(FuzzingCampaign):
    """Campaign that generates CSV reports for performance analysis"""
    
    def __init__(self):
        super().__init__()
        self.name = "Performance Analysis Demo"
        self.target = "192.168.1.100"
        self.iterations = 50
        
        # Generate CSV for data analysis and JSON for programmatic access
        self.report_formats = ['csv', 'json']
        
        self.output_network = False
        self.output_pcap = "performance_demo.pcap"
        self.rate_limit = 10  # 10 packets per second
        
    def build_packets(self):
        # Generate packets of varying sizes for performance testing
        packets = []
        for size in [100, 500, 1000, 1500]:
            payload = b"x" * size
            packets.append(IP(dst=self.target) / TCP(dport=80) / Raw(load=payload))
        return packets


class ComprehensiveReportCampaign(FuzzingCampaign):
    """Campaign that generates all supported report formats"""
    
    def __init__(self):
        super().__init__()
        self.name = "Comprehensive Report Demo"
        self.target = "192.168.1.100"
        self.iterations = 25
        
        # Generate all supported formats
        self.report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']
        
        self.output_network = False
        self.output_pcap = "comprehensive_demo.pcap"
        
    def build_packets(self):
        return [
            IP(dst=self.target) / TCP(dport=80) / Raw(load=b"HTTP test"),
            IP(dst=self.target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="test.com")),
            IP(dst=self.target) / TCP(dport=443) / Raw(load=b"TLS test"),
        ]


class FieldLevelFuzzWithReports(FuzzingCampaign):
    """Campaign demonstrating field-level fuzzing with detailed reporting"""
    
    def __init__(self):
        super().__init__()
        self.name = "Field-Level Fuzz with Reports"
        self.target = "192.168.1.100"
        self.iterations = 40
        
        # Generate detailed reports for field analysis
        self.report_formats = ['html', 'json']
        
        self.output_network = False
        self.output_pcap = "field_fuzz_demo.pcap"
        
    def build_packets(self):
        # Create packets with field-level fuzzing configuration
        tcp_packet = IP(dst=self.target) / TCP(dport=80) / Raw(load=b"test payload")
        
        # Configure specific fields for fuzzing
        tcp_layer = tcp_packet[TCP]
        tcp_layer.field_fuzz('sport').values = [80, 443, 22, 21, 25]
        tcp_layer.field_fuzz('dport').values = [80, 8080, 8443, 9000]
        tcp_layer.field_fuzz('flags').fuzz_weight = 0.8
        
        udp_packet = IP(dst=self.target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="fuzz.test"))
        udp_layer = udp_packet[UDP]
        udp_layer.field_fuzz('dport').values = [53, 5353, 853]
        
        return [tcp_packet, udp_packet]


# Usage examples for CLI
if __name__ == "__main__":
    print("Report Generation Examples")
    print("=" * 50)
    print()
    print("1. HTML Report (human-readable):")
    print("   python -m packetfuzz examples/basic/report_examples.py --campaign HTMLReportCampaign")
    print()
    print("2. Security Analysis (SARIF + HTML):")
    print("   python -m packetfuzz examples/basic/report_examples.py --campaign SecurityAnalysisCampaign")
    print()
    print("3. Performance Analysis (CSV + JSON):")
    print("   python -m packetfuzz examples/basic/report_examples.py --campaign PerformanceAnalysisCampaign")
    print()
    print("4. Comprehensive Reports (all formats):")
    print("   python -m packetfuzz examples/basic/report_examples.py --campaign ComprehensiveReportCampaign")
    print()
    print("5. Field-Level Fuzzing with Reports:")
    print("   python -m packetfuzz examples/basic/report_examples.py --campaign FieldLevelFuzzWithReports")
    print()
    print("CLI Report Format Examples:")
    print("=" * 30)
    print()
    print("Single format:")
    print("   python -m packetfuzz campaign.py --report-formats html")
    print()
    print("Multiple formats:")
    print("   python -m packetfuzz campaign.py --report-formats html json csv")
    print()
    print("All formats:")
    print("   python -m packetfuzz campaign.py --report-formats all")
    print()
    print("Environment variable:")
    print("   export PACKETFUZZ_REPORT_FORMATS='sarif,html'")
    print("   python -m packetfuzz campaign.py")
