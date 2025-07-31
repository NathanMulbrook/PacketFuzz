#!/usr/bin/env python3
"""
Configuration Template: Network Infrastructure Fuzzing

Reusable configuration classes for network infrastructure testing.
Includes DNS, DHCP, ARP, and other network protocol configurations.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
import random

class NetworkBaseCampaign(FuzzingCampaign):
    """Base configuration for network infrastructure fuzzing."""
    
    # Conservative settings for network infrastructure
    rate_limit = 1.0  # Slow rate to avoid network disruption
    capture_responses = True
    verbose = True
    
    # Common network ranges
    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16"
    ]
    
    # Common DNS servers
    DNS_SERVERS = [
        "8.8.8.8",        # Google
        "1.1.1.1",        # Cloudflare
        "208.67.222.222", # OpenDNS
        "9.9.9.9"         # Quad9
    ]
    
    def generate_random_ip(self, network="192.168.1.0/24"):
        """Generate a random IP in the given network."""
        import ipaddress
        net = ipaddress.IPv4Network(network, strict=False)
        return str(net.network_address + random.randint(1, net.num_addresses - 2))

class DNSFuzzCampaign(NetworkBaseCampaign):
    """DNS protocol fuzzing campaign."""
    name = "DNS Infrastructure Fuzzing"
    iterations = 10
    
    def __init__(self, dns_server="8.8.8.8"):
        super().__init__()
        self.target = dns_server
        
        # DNS query types to test
        self.query_types = [1, 2, 5, 12, 15, 16, 28, 33, 35, 39]  # A, NS, CNAME, PTR, MX, TXT, AAAA, SRV, NAPTR, DNAME
        
        # Test domains
        self.test_domains = [
            "example.com",
            "test.local", 
            "nonexistent.invalid",
            "very-long-domain-name-that-might-cause-issues.com",
            "short.co",
            "127.0.0.1",
            "localhost"
        ]
        
        # Create base DNS packet
        self.packet = IP(dst=dns_server) / UDP(dport=53) / DNS(
            rd=1, 
            qd=DNSQR(qname="example.com", qtype=1)
        )

class ARPFuzzCampaign(NetworkBaseCampaign):
    """ARP protocol fuzzing campaign."""
    name = "ARP Network Fuzzing"
    iterations = 6
    
    def __init__(self, target_network="192.168.1.0/24"):
        super().__init__()
        self.target_network = target_network
        self.target = "192.168.1.1"  # Typically gateway
        
        # ARP operation codes
        self.arp_ops = [1, 2, 3, 4]  # Request, Reply, RARP Request, RARP Reply
        
        # Create base ARP packet
        self.packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,  # ARP request
            pdst=self.generate_random_ip(target_network),
            psrc=self.generate_random_ip(target_network)
        )

class ICMPFuzzCampaign(NetworkBaseCampaign):
    """ICMP protocol fuzzing campaign."""
    name = "ICMP Network Fuzzing" 
    iterations = 8
    
    def __init__(self, target="192.168.1.1"):
        super().__init__()
        self.target = target
        
        # ICMP types to test
        self.icmp_types = [0, 3, 4, 5, 8, 11, 12, 13, 14, 15, 16, 17, 18]
        
        # Create base ICMP packet
        self.packet = IP(dst=target) / ICMP(type=8, code=0)  # Echo request

class DHCPFuzzCampaign(NetworkBaseCampaign):
    """DHCP protocol fuzzing campaign."""
    name = "DHCP Infrastructure Fuzzing"
    iterations = 5
    
    def __init__(self, dhcp_server="192.168.1.1"):
        super().__init__()
        self.target = dhcp_server
        
        # DHCP message types
        self.dhcp_message_types = [1, 2, 3, 4, 5, 6, 7, 8]  # Discover, Offer, Request, etc.
        
        # Create base DHCP packet
        self.packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=b"\x01\x02\x03\x04\x05\x06") /
            DHCP(options=[("message-type", "discover"), "end"])
        )

class NetworkDiscoveryCampaign(NetworkBaseCampaign):
    """Network discovery and reconnaissance campaign."""
    name = "Network Discovery"
    iterations = 15
    
    def __init__(self, target_network="192.168.1.0/24"):
        super().__init__()
        self.target_network = target_network
        self.target = "192.168.1.1"
        
        # Common service ports
        self.service_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        # Create base TCP SYN packet for port scanning
        target_ip = self.generate_random_ip(target_network)
        target_port = random.choice(self.service_ports)
        
        self.packet = IP(dst=target_ip) / TCP(
            dport=target_port,
            flags="S"  # SYN flag
        )

class RouterFuzzCampaign(NetworkBaseCampaign):
    """Router/Gateway fuzzing campaign."""
    name = "Router Infrastructure Fuzzing"
    iterations = 12
    
    def __init__(self, router_ip="192.168.1.1"):
        super().__init__()
        self.target = router_ip
        
        # Router management ports
        self.mgmt_ports = [80, 443, 23, 22, 161, 8080, 8443]
        
        # Create base packet targeting router management
        mgmt_port = random.choice(self.mgmt_ports)
        
        if mgmt_port in [80, 8080]:
            # HTTP management
            http_request = b"GET /admin HTTP/1.1\r\nHost: router\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
            self.packet = IP(dst=router_ip) / TCP(dport=mgmt_port) / http_request
        elif mgmt_port in [443, 8443]:
            # HTTPS management (simplified)
            self.packet = IP(dst=router_ip) / TCP(dport=mgmt_port) / b"\x16\x03\x01\x00\x01\x01"
        elif mgmt_port == 161:
            # SNMP
            self.packet = IP(dst=router_ip) / UDP(dport=161) / b"\x30\x19\x02\x01\x00\x04\x06public"
        else:
            # Generic TCP probe
            self.packet = IP(dst=router_ip) / TCP(dport=mgmt_port, flags="S")

# Configuration registry
NETWORK_CONFIGS = {
    'dns': DNSFuzzCampaign,
    'arp': ARPFuzzCampaign,
    'icmp': ICMPFuzzCampaign,
    'dhcp': DHCPFuzzCampaign,
    'discovery': NetworkDiscoveryCampaign,
    'router': RouterFuzzCampaign
}

def create_network_campaign(protocol, *args, **kwargs):
    """Factory function to create network infrastructure campaigns."""
    if protocol not in NETWORK_CONFIGS:
        raise ValueError(f"Unknown protocol: {protocol}")
    
    campaign_class = NETWORK_CONFIGS[protocol]
    return campaign_class(*args, **kwargs)

if __name__ == "__main__":
    print("=== Network Infrastructure Configuration Templates ===")
    print("Available protocols:")
    for protocol in NETWORK_CONFIGS.keys():
        print(f"  - {protocol}")
    print()
    print("Usage:")
    print("  from config.network_config import create_network_campaign")
    print("  campaign = create_network_campaign('dns', '8.8.8.8')")
    print("  campaign.execute()")
