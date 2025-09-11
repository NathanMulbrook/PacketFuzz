#!/usr/bin/env python3
"""
FuzzField Configuration Examples

Demonstrates comprehensive FuzzField configuration with:
- Custom values for precise control
- Dictionary-based fuzzing  
- Mutator-specific configuration
- Field descriptions and metadata
"""

from scapy.all import IP, TCP, UDP, Raw
from packetfuzz import FuzzingCampaign, FuzzField
from packetfuzz.sockets import RawIPConfig

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
                values=["S", "SA", "F", "R", "P", "FPU", ""],
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
    
    packet = (
        IP() /
        UDP(dport=53) /  # DNS fuzzing
        Raw(
            load=FuzzField(
                dictionaries=["dns_names.txt", "common_subdomains.txt"],
                description="DNS query fuzzing from wordlists"
            )
        )
    )
    
    def pre_send_callback(self, context, packet):
        """Construct proper DNS query format."""
        if packet.haslayer(Raw):
            # Convert dictionary payload to DNS format
            domain = packet[Raw].load
            if isinstance(domain, bytes):
                # Simple DNS query construction (normally you'd use DNS layer)
                dns_query = b"\x00\x01"  # Query ID
                dns_query += b"\x01\x00"  # Standard query
                dns_query += b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 query, 0 answers
                
                # Encode domain name
                for part in domain.decode('utf-8', errors='ignore').split('.'):
                    if part:
                        dns_query += bytes([len(part)]) + part.encode('utf-8', errors='ignore')
                dns_query += b"\x00"  # End of domain
                dns_query += b"\x00\x01\x00\x01"  # A record, IN class
                
                packet[Raw].load = dns_query
        return True

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
    
    def field_selection_callback(self, context, available_fields):
        """Custom field selection logic."""
        # Prioritize Raw.load field 70% of the time
        if "Raw.load" in available_fields and context.random.random() < 0.7:
            return ["Raw.load"]
        
        # Otherwise, prefer TCP fields
        tcp_fields = [f for f in available_fields if f.startswith("TCP.")]
        if tcp_fields:
            return [context.random.choice(tcp_fields)]
        
        return available_fields[:1]  # Default to first available
    
    def post_send_callback(self, context, packet, response=None):
        """Log advanced fuzzing results."""
        ip_len = packet[IP].len if packet.haslayer(IP) else 0
        tcp_seq = packet[TCP].seq if packet.haslayer(TCP) else 0
        payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
        
        print(f"Advanced fuzz: IP_len={ip_len}, TCP_seq=0x{tcp_seq:08x}, "
              f"payload_len={payload_len}")
        return True

def demonstrate_fuzzfield_features():
    """Show FuzzField configuration examples."""
    print("FuzzField Configuration Examples")
    print("=" * 40)
    
    # Show basic FuzzField construction
    basic_field = FuzzField(
        values=[80, 443, 8080],
        description="Common web ports"
    )
    print(f"Basic FuzzField: {basic_field}")
    
    # Show dictionary-based field
    dict_field = FuzzField(
        dictionaries=["passwords.txt", "usernames.txt"],
        description="Authentication fuzzing"
    )
    print(f"Dictionary FuzzField: {dict_field}")
    
    # Show mutator-controlled field
    mutator_field = FuzzField(
        values=[b"base_payload"],
        mutators={"libfuzzer": 1.0},
        description="Mutation-based fuzzing"
    )
    print(f"Mutator FuzzField: {mutator_field}")

def main():
    """Run FuzzField configuration demonstrations."""
    print("FuzzField Configuration Demonstrations")
    print("=" * 50)
    
    # Show configuration examples
    demonstrate_fuzzfield_features()
    
    print("\n" + "=" * 50)
    print("Running Fuzzing Campaigns:")
    
    # Run value-based campaign
    print("\n1. Value-Based Field Fuzzing:")
    value_campaign = ValueBasedFuzzCampaign()
    value_campaign.execute()
    
    # Run dictionary-based campaign
    print("\n2. Dictionary-Based Field Fuzzing:")
    dict_campaign = DictionaryBasedFuzzCampaign()
    dict_campaign.execute()
    
    # Run mutator-controlled campaign
    print("\n3. Mutator-Controlled Field Fuzzing:")
    mutator_campaign = MutatorControlledFuzzCampaign()
    mutator_campaign.execute()
    
    # Run advanced campaign
    print("\n4. Advanced FuzzField Configuration:")
    advanced_campaign = AdvancedFuzzFieldCampaign()
    advanced_campaign.execute()
    
    print("\nFuzzField configuration examples complete!")
    print("Generated PCAP files:")
    print("- value_based_fuzz.pcap")
    print("- dictionary_based_fuzz.pcap")
    print("- mutator_controlled_fuzz.pcap")
    print("- advanced_fuzzfield.pcap")

# Campaign registry for framework discovery
CAMPAIGNS = [
    ValueBasedFuzzCampaign,
    DictionaryBasedFuzzCampaign,
    MutatorControlledFuzzCampaign,
    AdvancedFuzzFieldCampaign
]

if __name__ == "__main__":
    main()
