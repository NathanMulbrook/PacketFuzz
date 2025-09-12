#!/usr/bin/env python3
"""
FuzzField Configuration Examples

Demonstrates comprehensive FuzzField configuration with:
- Custom values for precise control
- String lists for clean, readable fuzzing (StringListFuzzCampaign, HostnameFuzzCampaign)
- Dictionary-based fuzzing  
- Mutator-specific configuration
- Field descriptions and metadata

The string list approach (values=["string1", "string2", ...]) is particularly
clean and readable for many fuzzing scenarios.
"""

from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from packetfuzz import FuzzingCampaign, FuzzField
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class ValueBasedFuzzCampaign(FuzzingCampaign):
    """Demonstrates FuzzField with specific values."""
    name = "Value-Based Field Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 15
    output_network = False
    output_pcap = "value_based_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() /
        TCP(
            # Port fuzzing with specific high-value targets
            dport=FuzzField(
                values=[22, 23, 80, 443, 8080, 65535, 0, 1024],
                description="Common and edge-case ports"
            ),
            # Window size testing
            window=FuzzField(
                values=[0, 1, 512, 8192, 32768, 65535],
                description="TCP window sizes including edge cases"
            ),
            # Flag combinations
            flags=FuzzField(
                values=[2, 18, 1, 4, 8, 41, 0],  # S, SA, F, R, P, FPU, None
                description="TCP flag combinations"
            )
        ) /
        Raw(
            load=FuzzField(
                values=[
                    b"", 
                    b"GET / HTTP/1.1\r\n\r\n",
                    b"A" * 100,
                    b"\x00\x01\x02\x03",
                    b"../../../etc/passwd"
                ],
                description="HTTP and injection payloads"
            )
        )
    )
    
    def post_send_callback(self, context, packet, response=None):
        """Log the specific values being tested."""
        tcp = packet[TCP]
        raw_data = packet[Raw].load if packet.haslayer(Raw) else b""
        print(f"Testing: port={tcp.dport}, window={tcp.window}, "
              f"flags='{tcp.flags}', payload_len={len(raw_data)}")
        return True

class DictionaryBasedFuzzCampaign(FuzzingCampaign):
    """Demonstrates FuzzField with dictionary fuzzing."""
    name = "Dictionary-Based Field Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 20
    output_network = False
    output_pcap = "dictionary_based_fuzz.pcap"
    verbose = True
    
    # Use proper DNS layer instead of manual Raw packet construction
    packet = (
        IP() /
        UDP(dport=53) /
        DNS(
            rd=1,
            qd=DNSQR(
                qname=FuzzField(
                    dictionaries=["dns_names.txt", "common_subdomains.txt"],
                    description="DNS query fuzzing from wordlists"
                ),
                qtype="A"
            )
        )
    )

class StringListFuzzCampaign(FuzzingCampaign):
    """Demonstrates FuzzField with simple lists of strings - very clean and readable."""
    name = "String List Field Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 30
    output_network = False
    output_pcap = "string_list_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() /
        TCP(dport=80) /
        Raw(
            # HTTP requests with various methods and paths
            load=FuzzField(
                values=[
                    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "PUT /upload HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "DELETE /file HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HEAD /info HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                    "GET /../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "GET /test?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n"
                ],
                description="HTTP method and injection fuzzing"
            )
        )
    )

class HostnameFuzzCampaign(FuzzingCampaign):
    """Another example using string lists for hostname fuzzing."""
    name = "Hostname String List Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100") 
    iterations = 15
    output_network = False
    output_pcap = "hostname_list_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() /
        UDP(dport=53) /
        DNS(
            rd=1,
            qd=DNSQR(
                # Clean list of test hostnames
                qname=FuzzField(
                    values=[
                        "example.com",
                        "test.example.com", 
                        "admin.example.com",
                        "api.example.com",
                        "www.example.com",
                        "mail.example.com",
                        "ftp.example.com",
                        "localhost",
                        "127.0.0.1",
                        "::1",
                        "nonexistent.domain",
                        "very-long-hostname-that-might-cause-issues.example.com",
                        "",  # Empty hostname
                        "test..double-dot.com",  # Malformed
                        "underscore_test.com"  # RFC violation
                    ],
                    description="Hostname validation and edge case testing"
                ),
                qtype="A"
            )
        )
    )

class MutatorControlledFuzzCampaign(FuzzingCampaign):
    """Demonstrates FuzzField with specific mutator control."""
    name = "Mutator-Controlled Field Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 25
    output_network = False
    output_pcap = "mutator_controlled_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() /
        TCP(dport=8080) /
        Raw(
            load=FuzzField(
                values=[b"GET /api/users HTTP/1.1\r\nHost: target.com\r\n\r\n"],
                mutators={"libfuzzer": 0.7, "dictionary_only": 0.3},
                description="HTTP request with controlled mutations"
            )
        )
    )
    
    def post_mutation_callback(self, context, packet, field_name, original_value, mutated_value):
        """Track what mutations are being applied."""
        if field_name == "Raw.load":
            mutation_type = "unknown"
            if b"GET" not in mutated_value and b"GET" in original_value:
                mutation_type = "method_corruption"
            elif len(mutated_value) > len(original_value) * 2:
                mutation_type = "payload_expansion"
            elif b"\x00" in mutated_value:
                mutation_type = "null_injection"
            
            print(f"Mutation applied: {mutation_type}, "
                  f"size: {len(original_value)} -> {len(mutated_value)}")
        return True

class AdvancedFuzzFieldCampaign(FuzzingCampaign):
    """Demonstrates advanced FuzzField features."""
    name = "Advanced FuzzField Configuration"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 30
    output_network = False
    output_pcap = "advanced_fuzzfield.pcap"
    verbose = True
    
    packet = (
        IP(
            # IP length fuzzing with edge cases
            len=FuzzField(
                values=[20, 0, 65535, 100],
                description="IP length field edge cases"
            )
        ) /
        TCP(
            dport=443,
            seq=FuzzField(
                values=[0, 1, 0x7FFFFFFF, 0xFFFFFFFF],
                description="Sequence numbers including edge cases"
            ),
            ack=FuzzField(
                values=[0, 1, 0x7FFFFFFF, 0xFFFFFFFF],
                description="Acknowledgment numbers"
            )
        ) /
        Raw(
            load=FuzzField(
                values=[
                    b"\x16\x03\x01",  # TLS handshake
                    b"\x16\x03\x03",  # TLS 1.2
                    b"\x16\x03\x04",  # TLS 1.3
                    b"\x00" * 5,     # Null payload
                    b"\xFF" * 10     # Max bytes
                ],
                dictionaries=["tls_payloads.txt"],
                mutators={"libfuzzer": 1.0},
                fuzz_weight=0.9,  # High priority field
                description="TLS handshake fuzzing with multiple sources"
            )
        )
    )
 
    def post_send_callback(self, context, packet, response=None):
        """Log advanced fuzzing results."""
        ip_len = packet[IP].len if packet.haslayer(IP) else 0
        tcp_seq = packet[TCP].seq if packet.haslayer(TCP) else 0
        payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
        
        print(f"Advanced fuzz: IP_len={ip_len}, TCP_seq=0x{tcp_seq:08x}, "
              f"payload_len={payload_len}")
        return True

CAMPAIGNS = [
    ValueBasedFuzzCampaign,
    DictionaryBasedFuzzCampaign,
    StringListFuzzCampaign,
    HostnameFuzzCampaign,
    MutatorControlledFuzzCampaign,
    AdvancedFuzzFieldCampaign
]
