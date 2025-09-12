#!/usr/bin/env python3
"""
Callback System Examples

Demonstrates the callback system for custom fuzzing logic:
- Pre-send callbacks for packet modification
- Post-send callbacks for response analysis  
- Error and crash handling callbacks
- Monitor callbacks for ongoing analysis
- Dictionary field overrides as cleaner alternatives to callbacks

Note: For simple payload injection and field fuzzing, FuzzField with values/dictionaries 
is cleaner than custom callbacks. Use callbacks only for complex logic that can't be handled by FuzzField configuration.

Run with: python -m packetfuzz examples/intermediate/03_callback_basics.py --disable-network
"""

import time
import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.layers.http import HTTP, HTTPRequest

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

import time
import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.layers.http import HTTP, HTTPRequest

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

def tcp_pre_send_callback(context, packet):
    """Modify TCP packets before sending."""
    if TCP in packet:
        # Generate realistic sequence numbers
        packet[TCP].seq = random.randint(1000000, 4000000000)
        packet[TCP].ack = random.randint(1000000, 4000000000)
        print(f"Modified TCP seq={packet[TCP].seq}, ack={packet[TCP].ack}")
    
    return CallbackResult.SUCCESS

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --", 
    "' UNION SELECT * FROM admin --",
    "1' AND 1=1 --",
    "admin' --",
    "' OR 1=1 --",
    "1' OR '1'='1' --",
    "'; SELECT * FROM users; --"
]

DNS_MALFORMED_NAMES = [
    b"." * 63,  # Max label length
    b"a" * 255,  # Max name length  
    b"\x00\x01\x02\x03",  # Binary data
    b"test..example.com",  # Double dots
    b"very-long-subdomain-name-that-exceeds-normal-limits.example.com",
    b"",  # Empty name
    b"invalid..dns..name",  # Multiple double dots
    b"label-too-long-" + b"x" * 50 + b".example.com",  # Oversized label
    b"\xff\xfe\xfd.example.com",  # High-value bytes
    b"test.example.com" + b"\x00" * 10  # Null bytes at end
]

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
        print(f"Malformed DNS: {original_name}  {malformed_name[:50]}...")
    
    return CallbackResult.SUCCESS

class TCPCallbackCampaign(FuzzingCampaign):
    """TCP fuzzing with pre-send callbacks."""
    name = "TCP Callback Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_tcp_callback.pcap"
    output_network = False
    verbose = False
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET", Host=b"test.com")
    pre_send_callback = tcp_pre_send_callback

class TCPFuzzFieldCampaign(FuzzingCampaign):
    """TCP fuzzing using FuzzField for sequence/ack numbers (cleaner approach)."""
    name = "TCP FuzzField Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_tcp_fuzzfield.pcap"
    output_network = False
    verbose = False
    
    # Use FuzzField for realistic sequence/ack numbers instead of callback
    packet = IP() / TCP(
        seq=FuzzField(values=list(range(1000000, 4000000000, 100000000))),
        ack=FuzzField(values=list(range(1000000, 4000000000, 100000000)))
    ) / HTTP() / HTTPRequest(Path=b"/", Method=b"GET", Host=b"test.com")

class HTTPInjectionCampaign(FuzzingCampaign):
    """HTTP fuzzing with SQL injection via dictionary field override."""
    name = "HTTP Injection Dictionary"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_http_injection.pcap"
    output_network = False
    verbose = False
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(
        Path=FuzzField(values=[f"/search?q={payload}".encode() for payload in SQL_INJECTION_PAYLOADS]), 
        Method=b"GET", 
        Host=b"target.com"
    )

class HTTPRawInjectionCampaign(FuzzingCampaign):
    """Alternative HTTP injection using Raw layer for full control."""
    name = "HTTP Raw Injection Dictionary"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_http_raw_injection.pcap"
    output_network = False
    verbose = False
    
    # Raw HTTP request with fuzzed query parameter
    packet = IP() / TCP() / Raw(load=FuzzField(values=[
        f"GET /search?q={payload} HTTP/1.1\r\nHost: target.com\r\nUser-Agent: PacketFuzz\r\n\r\n".encode()
        for payload in SQL_INJECTION_PAYLOADS
    ]))


def response_capture_callback(context, packet, response):
    """
    Analyze responses and demonstrate the history tracking functionality.
    This callback shows how to use the fuzz_history feature to analyze
    response patterns over time.
    """
    if response:
        print(f"Response received: {len(response)} bytes")
        
        if context.fuzz_history:
            history_entry = context.fuzz_history[-1]
            response_time = history_entry.get_response_time()
            
            if response_time:
                print(f"Response time: {response_time:.2f} ms")
                
                if 'min_response_time' not in context.shared_data or response_time < context.shared_data['min_response_time']:
                    context.shared_data['min_response_time'] = response_time
                if 'max_response_time' not in context.shared_data or response_time > context.shared_data['max_response_time']:
                    context.shared_data['max_response_time'] = response_time
                
                if 'total_response_time' not in context.shared_data:
                    context.shared_data['total_response_time'] = 0
                    context.shared_data['response_count'] = 0
                
                context.shared_data['total_response_time'] += response_time
                context.shared_data['response_count'] += 1
                avg_time = context.shared_data['total_response_time'] / context.shared_data['response_count']
                
                print(f"Stats: min={context.shared_data.get('min_response_time', 0):.2f}ms, " + 
                      f"avg={avg_time:.2f}ms, " + 
                      f"max={context.shared_data.get('max_response_time', 0):.2f}ms")
    else:
        print("No response received")
    
    return CallbackResult.SUCCESS

class ResponseTrackingCampaign(FuzzingCampaign):
    """Campaign demonstrating response capture and history tracking."""
    name = "Response Tracking Callback"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_response_tracking.pcap"
    capture_responses = False
    output_network = False
    verbose = False
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET", Host=b"target.com")
    post_send_callback = response_capture_callback

class DNSMalformCampaign2(FuzzingCampaign):
    """DNS fuzzing with malformed names using FuzzField."""
    name = "DNS Malformation Dictionary"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_dns_malform.pcap"
    output_network = False
    
    packet = IP(dst="192.168.1.100") / UDP(dport=53) / DNS(
        rd=1, qd=DNSQR(qname=FuzzField(values=DNS_MALFORMED_NAMES), qtype="A")
    )

class DNSMalformCampaign(FuzzingCampaign):
    """DNS fuzzing with malformed names using FuzzField."""
    name = "DNS Malform Dictionary 2"
    socket_config = RawIPConfig(target="10.10.10.10")
    iterations = 1
    output_pcap = "intermediate_dns_malform2.pcap"
    output_network = False
    
    packet = IP() / UDP(dport=53) / DNS(
        rd=1, qd=DNSQR(qname=FuzzField(values=DNS_MALFORMED_NAMES))
    )

def response_analysis_callback(context, packet, response=None):
    """Analyze responses for interesting behavior."""
    if response:
        if TCP in response and response[TCP].flags & 0x04:  # RST flag
            print(f"TCP RST received - potential filtering detected")
            context.shared_data['interesting_responses'] = context.shared_data.get('interesting_responses', 0) + 1
            return CallbackResult.SUCCESS
        
        if hasattr(response, 'load') and len(response.load) > 1000:
            print(f"Large response ({len(response.load)} bytes) - potential buffer issue")
            context.shared_data['large_responses'] = context.shared_data.get('large_responses', 0) + 1
            return CallbackResult.SUCCESS
    
    return CallbackResult.SUCCESS

class ResponseAnalysisCampaign(FuzzingCampaign):
    """Campaign with response analysis callbacks."""
    name = "Response Analysis"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_pcap = "intermediate_response_analysis.pcap"
    capture_responses = False
    output_network = False
    verbose = False
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET", Host=b"test.com")
    post_send_callback = response_analysis_callback

def packet_preprocessing_callback(context, packet):
    """Preprocess packets before sending."""
    if TCP in packet and hasattr(packet[TCP], 'load'):
        timestamp = f"X-Timestamp: {int(time.time())}\r\n"
        original_load = packet[TCP].load.decode(errors='ignore')
        lines = original_load.split('\r\n')
        if len(lines) > 0:
            lines.insert(1, timestamp.strip())
            packet[TCP].load = '\r\n'.join(lines).encode()
            print(f"Added timestamp header")
    
    # Recalculate checksums
    if IP in packet:
        del packet[IP].chksum
    if TCP in packet:
        del packet[TCP].chksum
    
    return CallbackResult.SUCCESS

class PreprocessingCampaign(FuzzingCampaign):
    """Campaign with packet preprocessing."""
    name = "Preprocessing Callback"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 1
    output_network = False
    verbose = False
    output_pcap = "intermediate_preprocessing.pcap"
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/api/data", Method=b"GET", Host=b"api.com")
    pre_send_callback = packet_preprocessing_callback

# Campaign registry
CAMPAIGNS = [
    TCPCallbackCampaign,
    TCPFuzzFieldCampaign,
    HTTPInjectionCampaign,
    HTTPRawInjectionCampaign,
    ResponseTrackingCampaign,  # New response tracking campaign
    DNSMalformCampaign,
    DNSMalformCampaign2,
    ResponseAnalysisCampaign,
    PreprocessingCampaign
]

