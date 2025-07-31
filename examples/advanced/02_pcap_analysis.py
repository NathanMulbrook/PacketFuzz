#!/usr/bin/env python3
"""
Advanced Example 2: PCAP Analysis and Processing

Demonstrates sophisticated PCAP-based fuzzing with layer extraction,
binary analysis, and intelligent payload processing.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.utils import wrpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pcapfuzz import PcapFuzzCampaign
from fuzzing_framework import CallbackResult

class AdvancedHTTPExtractionCampaign(PcapFuzzCampaign):
    """Extract HTTP payloads with intelligent fuzzing and analysis."""
    name = "Advanced HTTP Extraction"
    pcap_folder = "regression_samples/"
    extract_layer = "TCP"
    repackage_in = "IP/TCP"
    fuzz_mode = "both"  # Field + binary fuzzing
    target = "192.168.1.100"
    iterations = 8
    rate_limit = 1.0
    output_pcap = "advanced_http_extraction.pcap"
    verbose = True
    
    def __init__(self):
        super().__init__()
        self.http_methods = set()
        self.attack_patterns = []
        self.response_codes = {}
    
    def pre_send_callback(self, context, packet):
        """Analyze and enhance HTTP packets before sending."""
        packet_bytes = bytes(packet)
        
        # Extract HTTP method
        if b"HTTP" in packet_bytes:
            for method in [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS"]:
                if packet_bytes.startswith(method):
                    self.http_methods.add(method.decode())
                    print(f"🌐 HTTP {method.decode()} request")
                    break
            
            # Inject attack patterns
            if b"GET /" in packet_bytes and b"?" not in packet_bytes:
                # Add SQL injection parameter
                injection = b"?id=1' OR '1'='1--"
                packet_bytes = packet_bytes.replace(b"GET /", b"GET /" + injection)
                if TCP in packet and hasattr(packet[TCP], 'load'):
                    packet[TCP].load = packet_bytes[packet_bytes.find(b"GET"):]
                    self.attack_patterns.append("SQL injection")
                    print(f"💉 Injected SQL payload")
            
            # Add fuzzing headers
            if b"\r\n\r\n" in packet_bytes:
                headers = b"X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 10.0.0.1\r\n"
                packet_bytes = packet_bytes.replace(b"\r\n\r\n", b"\r\n" + headers + b"\r\n")
                if TCP in packet and hasattr(packet[TCP], 'load'):
                    packet[TCP].load = packet_bytes[packet_bytes.find(b"GET"):]
                    print(f"🔧 Added fuzzing headers")
        
        return CallbackResult.SUCCESS
    
    def post_send_callback(self, context, packet, response=None):
        """Analyze HTTP responses."""
        if response and TCP in response and hasattr(response[TCP], 'load'):
            response_data = response[TCP].load
            
            # Extract response code
            if b"HTTP/" in response_data:
                try:
                    code_start = response_data.find(b"HTTP/1.") + 9
                    code = response_data[code_start:code_start+3].decode()
                    self.response_codes[code] = self.response_codes.get(code, 0) + 1
                    print(f"📊 HTTP {code} response")
                except:
                    pass
            
            # Check for interesting response patterns
            interesting_patterns = [
                (b"error", "Error message"),
                (b"exception", "Exception trace"),
                (b"admin", "Admin interface"),
                (b"debug", "Debug information"),
                (b"sql", "SQL error"),
                (b"stack trace", "Stack trace")
            ]
            
            for pattern, description in interesting_patterns:
                if pattern in response_data.lower():
                    print(f"🚨 Found {description}")
                    context.shared_data['interesting_responses'] = context.shared_data.get('interesting_responses', 0) + 1
        
        return CallbackResult.SUCCESS

class AdvancedBinaryAnalysisCampaign(PcapFuzzCampaign):
    """Binary-level protocol analysis and fuzzing."""
    name = "Advanced Binary Analysis"
    pcap_folder = "regression_samples/"
    extract_layer = "UDP"
    repackage_in = "IP/UDP"
    fuzz_mode = "binary"
    target = "192.168.1.200"
    iterations = 6
    output_pcap = "advanced_binary_analysis.pcap"
    verbose = True
    
    def __init__(self):
        super().__init__()
        self.binary_stats = {
            'total_bytes': 0,
            'null_bytes': 0,
            'printable_bytes': 0,
            'high_entropy': 0
        }
    
    def pre_send_callback(self, context, packet):
        """Analyze binary patterns."""
        if UDP in packet and hasattr(packet[UDP], 'load'):
            payload = packet[UDP].load
            self.binary_stats['total_bytes'] += len(payload)
            
            # Count null bytes
            null_count = payload.count(b'\x00')
            self.binary_stats['null_bytes'] += null_count
            
            # Count printable bytes
            printable_count = sum(1 for b in payload if 32 <= b <= 126)
            self.binary_stats['printable_bytes'] += printable_count
            
            # Simple entropy check
            unique_bytes = len(set(payload))
            if unique_bytes > len(payload) * 0.7:  # High diversity
                self.binary_stats['high_entropy'] += 1
                print(f"🎲 High entropy payload ({unique_bytes} unique bytes)")
            
            print(f"🔢 Binary stats: {len(payload)} bytes, {null_count} nulls, {printable_count} printable")
        
        return CallbackResult.SUCCESS

class AdvancedLayerFuzzCampaign(PcapFuzzCampaign):
    """Multi-layer fuzzing with protocol switching."""
    name = "Advanced Layer Fuzzing"
    pcap_folder = "regression_samples/"
    extract_layer = "IP"
    fuzz_mode = "field"
    target = "192.168.1.50"
    iterations = 10
    output_pcap = "advanced_layer_fuzz.pcap"
    verbose = True
    
    def __init__(self):
        super().__init__()
        self.layer_mutations = {
            'IP': 0,
            'TCP': 0,
            'UDP': 0,
            'DNS': 0,
            'Payload': 0
        }
        self.protocol_switches = 0
    
    def pre_send_callback(self, context, packet):
        """Apply layer-specific mutations."""
        import random
        
        # Random IP modifications
        if IP in packet:
            # Occasionally modify IP fields
            if random.random() < 0.3:
                packet[IP].ttl = random.choice([0, 1, 255, 64])
                packet[IP].flags = random.choice([0, 1, 2, 4])
                self.layer_mutations['IP'] += 1
                print(f"🌐 Modified IP layer (TTL={packet[IP].ttl})")
        
        # Protocol switching
        if TCP in packet and random.random() < 0.2:
            # Convert TCP to UDP
            tcp_port = packet[TCP].dport
            tcp_load = packet[TCP].load if hasattr(packet[TCP], 'load') else b""
            
            # Replace TCP with UDP
            new_packet = packet[IP] / UDP(dport=tcp_port) / tcp_load
            packet = new_packet
            self.protocol_switches += 1
            self.layer_mutations['UDP'] += 1
            print(f"🔄 Switched TCP to UDP (port {tcp_port})")
        
        elif UDP in packet:
            # DNS-specific modifications
            if packet[UDP].dport == 53:
                self.layer_mutations['DNS'] += 1
                print(f"🌐 DNS packet to port 53")
            else:
                self.layer_mutations['UDP'] += 1
        
        # Payload modifications
        for layer in [TCP, UDP]:
            if layer in packet and hasattr(packet[layer], 'load'):
                if random.random() < 0.4:
                    original_load = packet[layer].load
                    # Add random bytes
                    packet[layer].load = original_load + bytes([random.randint(0, 255) for _ in range(5)])
                    self.layer_mutations['Payload'] += 1
                    print(f"📦 Extended payload by 5 bytes")
        
        return CallbackResult.SUCCESS
    
    def post_send_callback(self, context, packet, response=None):
        """Track mutation effectiveness."""
        print(f"📈 Mutation stats: {self.layer_mutations}")
        if self.protocol_switches > 0:
            print(f"🔄 Protocol switches: {self.protocol_switches}")
        
        return CallbackResult.SUCCESS

def create_sample_pcaps():
    """Create sample PCAP files for advanced testing."""
    sample_dir = "regression_samples"
    if not os.path.exists(sample_dir):
        os.makedirs(sample_dir)
    
    # Create complex HTTP traffic
    http_packets = [
        IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=12345, dport=80)/b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
        IP(src="93.184.216.34", dst="192.168.1.10")/TCP(sport=80, dport=12345)/b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
    ]
    wrpcap(f"{sample_dir}/advanced_http.pcap", http_packets)
    
    # Create binary UDP traffic  
    binary_packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")/UDP(sport=5000, dport=5001)/b"\x01\x02\x03\x04\x00\x00\xff\xff",
        IP(src="192.168.1.20", dst="192.168.1.10")/UDP(sport=5001, dport=5000)/b"\xff\xfe\xfd\xfc\x00\x01\x02\x03"
    ]
    wrpcap(f"{sample_dir}/binary_protocol.pcap", binary_packets)
    
    print("✓ Created advanced sample PCAP files")

# Campaign registry
CAMPAIGNS = [
    AdvancedHTTPExtractionCampaign,
    AdvancedBinaryAnalysisCampaign,
    AdvancedLayerFuzzCampaign
]

def main():
    """Run advanced PCAP analysis examples."""
    print("=== Advanced Example 2: PCAP Analysis and Processing ===")
    print("Demonstrates sophisticated PCAP-based fuzzing and analysis")
    print()
    
    # Create sample PCAPs if needed
    if not os.path.exists("regression_samples/"):
        print("Setting up advanced regression samples...")
        create_sample_pcaps()
        print()
    
    print("🔬 Advanced PCAP Features:")
    print("   • HTTP payload extraction and injection")
    print("   • Binary-level protocol analysis")
    print("   • Multi-layer fuzzing with protocol switching")
    print("   • Intelligent response pattern detection")
    print()
    
    results = []
    for campaign_class in CAMPAIGNS:
        campaign = campaign_class()
        
        print(f"🚀 Running {campaign.name}")
        print(f"   Target: {campaign.target}")
        print(f"   Mode: {campaign.fuzz_mode}")
        print(f"   Layer: {campaign.extract_layer if hasattr(campaign, 'extract_layer') else 'N/A'}")
        
        result = campaign.execute()  
        results.append(result)
        
        if result:
            print(f"   ✓ Success - {campaign.output_pcap}")
            
            # Show campaign-specific statistics
            if hasattr(campaign, 'http_methods') and campaign.http_methods:
                print(f"   📊 HTTP methods: {', '.join(campaign.http_methods)}")
            
            if hasattr(campaign, 'attack_patterns') and campaign.attack_patterns:
                print(f"   💉 Attack patterns: {', '.join(campaign.attack_patterns)}")
            
            if hasattr(campaign, 'response_codes') and campaign.response_codes:
                codes = [f"{k}:{v}" for k, v in campaign.response_codes.items()]
                print(f"   📊 Response codes: {', '.join(codes)}")
            
            if hasattr(campaign, 'binary_stats') and campaign.binary_stats['total_bytes'] > 0:
                stats = campaign.binary_stats
                print(f"   � Binary analysis: {stats['total_bytes']} bytes, {stats['high_entropy']} high entropy")
            
            if hasattr(campaign, 'layer_mutations') and any(campaign.layer_mutations.values()):
                mutations = [f"{k}:{v}" for k, v in campaign.layer_mutations.items() if v > 0]
                print(f"   🔧 Layer mutations: {', '.join(mutations)}")
        else:
            print(f"   ✗ Failed")
        print()
    
    success_count = sum(results)
    print(f"📊 Summary: {success_count}/{len(CAMPAIGNS)} campaigns successful")
    
    print("\n🎯 Advanced PCAP Techniques:")
    print("   • Layer extraction with intelligent repackaging")
    print("   • Protocol-aware payload injection")
    print("   • Binary pattern analysis and entropy detection")
    print("   • Dynamic protocol switching during fuzzing")
    print("   • Response pattern matching and anomaly detection")
    
    return all(results)

if __name__ == "__main__":
    main()
