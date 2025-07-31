#!/usr/bin/env python3
"""
Utility to create sample PCAP files for testing and demonstrations.

This script generates various sample PCAP files containing:
- DNS query packets
- HTTP request packets
- Custom UDP protocol packets
- Ethernet frame packets

The generated PCAP files are saved in the 'regression_samples' directory.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Correct imports for Scapy layers and protocols
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap

def create_sample_pcaps():
    """
    Create sample PCAP files for testing.
    
    Creates various PCAP files containing different protocol samples:
    - DNS queries and responses
    - HTTP requests with potential injection payloads
    - Custom UDP protocol communications
    - Layer 2 Ethernet frames
    - Binary protocol data
    
    Files are saved to the pcaps/ directory for use in testing and examples.
    """
    
    # DNS query packets
    dns_packets = [
        IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(qd=DNSQR(qname="example.com")),
        IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=12346, dport=53)/DNS(qd=DNSQR(qname="test.org")),
        # Include potentially suspicious domain for testing malicious payload detection
        IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=12347, dport=53)/DNS(qd=DNSQR(qname="malicious-site.evil")),
    ]
    
    # HTTP request packets
    http_packets = [
        IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=45678, dport=80)/Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=45679, dport=80)/Raw(b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 25\r\n\r\nusername=admin&password=test"),
        # Include SQL injection payload for testing security fuzzing
        IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=45680, dport=80)/Raw(b"GET /admin.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]
    
    # Custom UDP protocol packets
    custom_packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=8888, dport=9999)/Raw(b"CUSTOM_PROTO_HANDSHAKE"),
        IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=8888, dport=9999)/Raw(b"CUSTOM_PROTO_DATA_PAYLOAD_123456"),
        # Include potential command injection for security testing
        IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=8888, dport=9999)/Raw(b"CUSTOM_PROTO_COMMAND_EXECUTE_admin"),
    ]
    
    # Ethernet frame packets (Layer 2)
    ethernet_packets = [
        # Basic L2 data packet
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")/IP(src="172.16.0.1", dst="172.16.0.2")/UDP(sport=1234, dport=5678)/Raw(b"L2_DATA"),
        # L2 HTTP request for protocol stack testing
        Ether(src="aa:bb:cc:dd:ee:03", dst="aa:bb:cc:dd:ee:04")/IP(src="172.16.0.3", dst="172.16.0.4")/TCP(sport=9876, dport=80)/Raw(b"L2_HTTP_REQUEST"),
    ]
    
    # Write PCAP files
    regression_dir = Path("regression_samples")
    regression_dir.mkdir(exist_ok=True)
    
    wrpcap(str(regression_dir / "dns_queries.pcap"), dns_packets)
    wrpcap(str(regression_dir / "http_requests.pcap"), http_packets)
    wrpcap(str(regression_dir / "custom_protocol.pcap"), custom_packets)
    wrpcap(str(regression_dir / "ethernet_frames.pcap"), ethernet_packets)
    
    print("Sample PCAP files created in regression_samples/:")
    print("  - dns_queries.pcap: DNS query packets")
    print("  - http_requests.pcap: HTTP request packets")
    print("  - custom_protocol.pcap: Custom UDP protocol packets")
    print("  - ethernet_frames.pcap: Ethernet frame packets")

if __name__ == "__main__":
    create_sample_pcaps()
