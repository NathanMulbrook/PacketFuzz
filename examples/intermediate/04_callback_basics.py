#!/usr/bin/env python3
"""
Intermediate Example 4: Callback System Basics

Shows how to use callback functions for custom fuzzing logic,
data transformation, and result processing.
"""

import sys
import os
import time
import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult

def tcp_pre_send_callback(context, packet):
    """Modify TCP packets before sending."""
    if TCP in packet:
        # Generate realistic sequence numbers
        packet[TCP].seq = random.randint(1000000, 4000000000)
        packet[TCP].ack = random.randint(1000000, 4000000000)
        print(f"🔧 Modified TCP seq={packet[TCP].seq}, ack={packet[TCP].ack}")
    
    return CallbackResult.SUCCESS

def payload_injection_callback(context, packet):
    """Inject SQL injection payloads into HTTP requests."""
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM admin --",
        "1' AND 1=1 --"
    ]
    
    if TCP in packet and hasattr(packet[TCP], 'load'):
        original_load = packet[TCP].load.decode(errors='ignore')
        if 'q=' in original_load:
            # Replace query parameter with SQL injection
            payload = random.choice(sql_payloads)
            new_load = original_load.replace('test', payload)
            packet[TCP].load = new_load.encode()
            print(f"💉 Injected payload: {payload}")
    
    return CallbackResult.SUCCESS

def dns_malform_callback(context, packet):
    """Generate malformed DNS queries."""
    malformed_names = [
        b"." * 63,  # Max label length
        b"a" * 255,  # Max name length
        b"\x00\x01\x02\x03",  # Binary data
        b"test..example.com",  # Double dots
        b"very-long-subdomain-name-that-exceeds-normal-limits.example.com"
    ]
    
    if DNS in packet and packet[DNS].qd:
        original_name = packet[DNS].qd.qname
        malformed_name = random.choice(malformed_names)
        packet[DNS].qd.qname = malformed_name
        print(f"🚨 Malformed DNS: {original_name} → {malformed_name[:50]}...")
    
    return CallbackResult.SUCCESS

class TCPCallbackCampaign(FuzzingCampaign):
    """TCP fuzzing with pre-send callbacks."""
    name = "TCP Callback Fuzzing"
    target = "192.168.1.100"
    iterations = 8
    output_pcap = "intermediate_tcp_callback.pcap"
    
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
    pre_send_callback = tcp_pre_send_callback

class HTTPInjectionCampaign(FuzzingCampaign):
    """HTTP fuzzing with payload injection callbacks."""
    name = "HTTP Injection Callback"
    target = "192.168.1.100"
    iterations = 6
    output_pcap = "intermediate_http_injection.pcap"
    
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / b"GET /search?q=test HTTP/1.1\r\nHost: target.com\r\n\r\n"
    pre_send_callback = payload_injection_callback

class DNSMalformCampaign(FuzzingCampaign):
    """DNS fuzzing with malformed name callbacks."""
    name = "DNS Malform Callback"
    target = "8.8.8.8"
    iterations = 5
    output_pcap = "intermediate_dns_malform.pcap"
    
    packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    pre_send_callback = dns_malform_callback

def response_analysis_callback(context, packet, response=None):
    """Analyze responses for interesting behavior."""
    if response:
        # Check for error responses
        if TCP in response and response[TCP].flags & 0x04:  # RST flag
            print(f"🚨 TCP RST received - potential filtering detected")
            context.shared_data['interesting_responses'] = context.shared_data.get('interesting_responses', 0) + 1
            return CallbackResult.SUCCESS
        
        # Check payload size
        if hasattr(response, 'load') and len(response.load) > 1000:
            print(f"📊 Large response ({len(response.load)} bytes) - potential buffer issue")
            context.shared_data['large_responses'] = context.shared_data.get('large_responses', 0) + 1
            return CallbackResult.SUCCESS
    
    return CallbackResult.SUCCESS

class ResponseAnalysisCampaign(FuzzingCampaign):
    """Campaign with response analysis callbacks."""
    name = "Response Analysis"
    target = "192.168.1.100"
    iterations = 4
    output_pcap = "intermediate_response_analysis.pcap"
    capture_responses = True
    
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
    post_send_callback = response_analysis_callback

def packet_preprocessing_callback(context, packet):
    """Preprocess packets before sending."""
    # Add timestamp header
    if TCP in packet and hasattr(packet[TCP], 'load'):
        timestamp = f"X-Timestamp: {int(time.time())}\r\n"
        original_load = packet[TCP].load.decode(errors='ignore')
        # Insert timestamp after the first line
        lines = original_load.split('\r\n')
        if len(lines) > 0:
            lines.insert(1, timestamp.strip())
            packet[TCP].load = '\r\n'.join(lines).encode()
            print(f"⏰ Added timestamp header")
    
    # Recalculate checksums
    if IP in packet:
        del packet[IP].chksum
    if TCP in packet:
        del packet[TCP].chksum
    
    return CallbackResult.SUCCESS

class PreprocessingCampaign(FuzzingCampaign):
    """Campaign with packet preprocessing."""
    name = "Preprocessing Callback"
    target = "192.168.1.100"
    iterations = 3
    output_pcap = "intermediate_preprocessing.pcap"
    
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / b"GET /api/data HTTP/1.1\r\nHost: api.com\r\n\r\n"
    pre_send_callback = packet_preprocessing_callback

# Campaign registry
CAMPAIGNS = [
    TCPCallbackCampaign,
    HTTPInjectionCampaign,
    DNSMalformCampaign,
    ResponseAnalysisCampaign,
    PreprocessingCampaign
]

def main():
    print("=== Intermediate Example 4: Callback System Basics ===")
    print("Demonstrates callback functions for custom fuzzing logic")
    print()
    
    print("🔧 Callback Types:")
    print("   • Pre-send Callbacks: Modify packets before transmission")
    print("   • Post-send Callbacks: Analyze responses and results")
    print("   • Campaign-level: Applied to all packets in the campaign")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"🎯 Running {campaign.name}")
        print(f"   Target: {campaign.target}")
        
        # Show callback types
        callback_types = []
        if hasattr(campaign, 'pre_send_callback') and campaign.pre_send_callback:
            callback_types.append("pre-send")
        if hasattr(campaign, 'post_send_callback') and campaign.post_send_callback:
            callback_types.append("post-send")
        
        if callback_types:
            print(f"   Callbacks: {', '.join(callback_types)}")
        
        result = campaign.execute()
        results.append(result)
        
        if result:
            print(f"   ✓ Success - {campaign.output_pcap}")
        else:
            print(f"   ✗ Failed")
        print()
    
    success_count = sum(results)
    print(f"📊 Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    print("\n💡 Callback Best Practices:")
    print("   • Return CallbackResult.SUCCESS for normal operation")
    print("   • Use context.shared_data for state between callbacks")
    print("   • Pre-send callbacks can modify packets in-place")
    print("   • Post-send callbacks analyze responses and capture data")
    print("   • Always handle exceptions within callback functions")
    
    return all(results)

if __name__ == "__main__":
    main()
