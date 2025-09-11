#!/usr/bin/env python3
"""
PCAP-Based Fuzzing Examples

Demonstrates PcapFuzzCampaign for fuzzing packets from PCAP files:
- Layer extraction and repackaging
- Binary and field-level fuzzing modes  
- PCAP processing with custom analysis
- Multiple fuzzing strategies

Run with: python -m packetfuzz examples/advanced/02_pcap_fuzzing.py --disable-network
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS

from packetfuzz.pcapfuzz import PcapFuzzCampaign
from packetfuzz.fuzzing_framework import CallbackResult
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

class HTTPExtractionCampaign(PcapFuzzCampaign):
    """Extract HTTP payloads and apply field-level fuzzing."""
    name = "HTTP Payload Extraction"
    pcap_folder = "regression_samples/"
    fuzz_mode = "field"  # Field-level fuzzing with dictionaries
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 8
    output_pcap = "http_extraction.pcap"
    output_network = False
    verbose = True
    
    def __init__(self):
        super().__init__()
        # Configure layer extraction using properties (not class attributes)
        self.extract_at_layer = "TCP"  # Extract TCP payload
        self.repackage_template = IP() / TCP()  # Repackage in new headers
        self.http_requests = []
    
    def pre_send_callback(self, context, packet):
        """Track HTTP requests being fuzzed."""
        packet_bytes = bytes(packet)
        if b"GET " in packet_bytes or b"POST " in packet_bytes:
            method = "GET" if b"GET " in packet_bytes else "POST" 
            self.http_requests.append(method)
            print(f"Fuzzing {method} request #{len(self.http_requests)}")
        return CallbackResult.SUCCESS

class BinaryProtocolCampaign(PcapFuzzCampaign):
    """Binary-level fuzzing for unknown protocols."""
    name = "Binary Protocol Fuzzing"
    pcap_folder = "regression_samples/"  
    fuzz_mode = "binary"  # Binary mutations with libfuzzer
    socket_config = RawIPConfig(target="10.0.0.1")
    iterations = 10
    output_pcap = "binary_protocol.pcap"
    output_network = False
    verbose = True
    
    def __init__(self):
        super().__init__()
        self.extract_at_layer = "UDP"  # Extract UDP payloads
        self.repackage_template = IP() / UDP(dport=53)  # Repackage as DNS-like
        self.binary_stats = {"packets": 0, "avg_size": 0}
    
    def pre_send_callback(self, context, packet):
        """Analyze binary packet properties."""
        if UDP in packet:
            payload = bytes(packet[UDP])
            self.binary_stats["packets"] += 1
            current_avg = self.binary_stats["avg_size"]
            # Running average calculation
            new_avg = (current_avg * (self.binary_stats["packets"] - 1) + len(payload)) / self.binary_stats["packets"]
            self.binary_stats["avg_size"] = int(new_avg)
            print(f"Binary packet #{self.binary_stats['packets']}: {len(payload)} bytes (avg: {new_avg:.1f})")
        return CallbackResult.SUCCESS

class LayerFilteringCampaign(PcapFuzzCampaign):
    """Demonstrate layer filtering capabilities."""
    name = "Layer Filtering"
    pcap_folder = "regression_samples/"
    fuzz_mode = "both"  # Both field and binary fuzzing
    socket_config = RawIPConfig(target="127.0.0.1")
    iterations = 6  
    output_pcap = "layer_filtering.pcap"
    output_network = False
    verbose = True
    
    def __init__(self):
        super().__init__()
        # Only include specific layers in processing
        self.include_layers = ["IP", "UDP", "DNS"]  
        # This excludes Raw, TCP, HTTP, etc.
        self.protocol_counts = {}
    
    def pre_send_callback(self, context, packet):
        """Count protocols after layer filtering."""
        # Walk through packet layers
        current = packet
        layers_found = []
        while current:
            layer_name = current.__class__.__name__
            layers_found.append(layer_name)
            current = current.payload if hasattr(current, 'payload') else None
        
        for layer in layers_found:
            self.protocol_counts[layer] = self.protocol_counts.get(layer, 0) + 1
        
        print(f"Packet layers after filtering: {' -> '.join(layers_found)}")
        return CallbackResult.SUCCESS

class CombinedFuzzingCampaign(PcapFuzzCampaign):
    """Advanced campaign combining multiple PCAP techniques."""
    name = "Combined PCAP Fuzzing"
    pcap_folder = "regression_samples/"
    fuzz_mode = "both"  # Field + binary fuzzing
    socket_config = RawIPConfig(target="192.168.1.50")
    iterations = 12
    output_pcap = "combined_fuzzing.pcap"
    output_network = False
    verbose = True
    
    def __init__(self):
        super().__init__()
        # Extract IP layer and above
        self.extract_at_layer = "IP"
        # Exclude Raw layers to focus on structured protocols
        self.exclude_layers = ["Raw", "Padding"]
        self.packet_analysis = {"structured": 0, "raw": 0}
    
    def pre_send_callback(self, context, packet):
        """Analyze packet structure complexity."""
        layer_count = 0
        current = packet
        has_structured_data = False
        
        while current:
            layer_count += 1
            # Check for structured protocols
            if any(proto in current.__class__.__name__ for proto in ["HTTP", "DNS", "DHCP"]):
                has_structured_data = True
            current = current.payload if hasattr(current, 'payload') else None
        
        if has_structured_data:
            self.packet_analysis["structured"] += 1
            print(f"Structured packet with {layer_count} layers")
        else:
            self.packet_analysis["raw"] += 1
            print(f"Raw/binary packet with {layer_count} layers")
        
        return CallbackResult.SUCCESS

# Register campaigns for CLI discovery
CAMPAIGNS = [
    HTTPExtractionCampaign,
    BinaryProtocolCampaign,
    LayerFilteringCampaign,
    CombinedFuzzingCampaign
]

if __name__ == "__main__":
    print("Running PCAP-based fuzzing examples...")
    
    for campaign_class in CAMPAIGNS:
        print(f"\n=== {campaign_class.__name__} ===")
        campaign_class().execute()
