#!/usr/bin/env python3
"""
PCAP Fuzzing Demo - Interactive PCAP Analysis and Fuzzing

This demo provides an interactive exploration of PCAP-based fuzzing,
showing layer analysis, payload extraction, and different fuzzing modes.
"""

import os
import sys
from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import rdpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pcapfuzz import PcapFuzzCampaign

def analyze_pcap_file(pcap_file):
    """Analyze a PCAP file and show packet structure."""
    if not os.path.exists(pcap_file):
        print(f"❌ PCAP file not found: {pcap_file}")
        return None
    
    print(f"📁 Analyzing PCAP file: {pcap_file}")
    print("-" * 50)
    
    try:
        packets = rdpcap(pcap_file)
        print(f"📊 Total packets: {len(packets)}")
        
        # Analyze first few packets
        for i, packet in enumerate(packets[:3]):
            print(f"\n📦 Packet {i+1}:")
            print(f"   Summary: {packet.summary()}")
            print(f"   Layers: {[layer.name for layer in packet.layers()]}")
            
            # Show layer details
            if packet.haslayer(IP):
                ip = packet[IP]
                print(f"   IP: {ip.src} → {ip.dst}")
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                print(f"   TCP: {tcp.sport} → {tcp.dport} [Flags: {tcp.flags}]")
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                print(f"   UDP: {udp.sport} → {udp.dport}")
            
            if packet.haslayer(Raw):
                raw = packet[Raw]
                payload_preview = raw.load[:50] if len(raw.load) > 50 else raw.load
                print(f"   Payload: {len(raw.load)} bytes - {payload_preview}")
        
        return packets
        
    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")
        return None

def demo_fuzz_modes():
    """Demonstrate different fuzzing modes."""
    print("\n=== Fuzzing Modes Demo ===")
    print()
    
    modes = [
        ("none", "Regression testing - replay original packets"),
        ("field", "Dictionary-based field fuzzing"),
        ("binary", "Binary mutation with libFuzzer"),
        ("both", "Combined field and binary fuzzing")
    ]
    
    for mode, description in modes:
        print(f"🔧 {mode.upper()} Mode: {description}")
    
    print()

class InteractivePcapCampaign(PcapFuzzCampaign):
    """Interactive PCAP campaign for demonstration."""
    
    target = "127.0.0.1"
    iterations = 3
    rate_limit_per_second = 1
    
    def __init__(self, pcap_file, fuzz_mode="field", target_layer="UDP"):
        super().__init__()
        self.pcap_file = pcap_file
        self.fuzz_mode = fuzz_mode
        self.target_layer = target_layer
    
    def demo_packet_processing(self):
        """Demonstrate how packets are processed."""
        print(f"\n🔍 Processing PCAP with mode: {self.fuzz_mode}")
        print(f"   Target layer: {self.target_layer}")
        
        try:
            # Load and process first packet
            packets = rdpcap(self.pcap_file)
            if not packets:
                print("❌ No packets in PCAP file")
                return
            
            original_packet = packets[0]
            print(f"\n📦 Original packet: {original_packet.summary()}")
            
            # Extract payload based on target layer
            payload = self._extract_layer(original_packet, self.target_layer)
            if payload:
                payload_data = bytes(payload) if hasattr(payload, '__bytes__') else str(payload)
                print(f"📄 Extracted payload ({len(payload_data)} bytes): {payload_data[:50]}...")
                
                # Show how fuzzing would modify this
                if self.fuzz_mode == "field":
                    print("🎯 Field fuzzing would replace dictionary-mapped fields")
                elif self.fuzz_mode == "binary":
                    print("🔀 Binary fuzzing would mutate raw bytes")
                elif self.fuzz_mode == "both":
                    print("🎯🔀 Combined fuzzing would do both field and binary mutations")
                else:
                    print("📋 Regression mode would replay unchanged")
            else:
                print("⚠️  No payload found for target layer")
                
        except Exception as e:
            print(f"❌ Error processing packet: {e}")

def interactive_demo():
    """Run interactive PCAP fuzzing demo."""
    print("=== PCAP Fuzzing Interactive Demo ===")
    print()
    print("This demo explores PCAP-based fuzzing capabilities.")
    print("We'll analyze existing PCAP files and show different fuzzing approaches.")
    print()
    
    # Find available PCAP files
    pcap_files = []
    base_dir = Path(__file__).parent.parent.parent
    
    for pcap_file in base_dir.glob("*.pcap"):
        pcap_files.append(pcap_file.name)
    
    if not pcap_files:
        print("⚠️  No PCAP files found in project directory")
        print("   Creating a sample packet for demonstration...")
        
        # Create sample packet
        sample_packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
        
        print(f"📦 Sample packet: {sample_packet.summary()}")
        print(f"   Layers: {[layer.name for layer in sample_packet.layers()]}")
        
        return
    
    print(f"📁 Found {len(pcap_files)} PCAP files:")
    for i, pcap_file in enumerate(pcap_files, 1):
        print(f"   {i}. {pcap_file}")
    print()
    
    # Analyze first PCAP file
    selected_pcap = pcap_files[0]
    print(f"🔍 Analyzing: {selected_pcap}")
    
    packets = analyze_pcap_file(selected_pcap)
    if not packets:
        return
    
    # Demo fuzzing modes
    demo_fuzz_modes()
    
    # Interactive campaign demo
    print("=== Campaign Configuration Demo ===")
    print()
    
    fuzz_modes = ["none", "field", "binary", "both"]
    target_layers = ["UDP", "TCP", "IP", "Ethernet"]
    
    for mode in fuzz_modes[:2]:  # Demo first two modes
        print(f"\n🎯 Demo: {mode.upper()} mode fuzzing")
        print("-" * 30)
        
        campaign = InteractivePcapCampaign(
            pcap_file=selected_pcap,
            fuzz_mode=mode,
            target_layer="UDP"
        )
        
        campaign.demo_packet_processing()
    
    print()
    print("=== Advanced Features Demo ===")
    print()
    
    print("🔧 Layer Targeting:")
    print("   • Ethernet: Fuzz L2 headers (MAC addresses, etc.)")
    print("   • IP: Fuzz L3 headers (IP addresses, options, etc.)")
    print("   • TCP/UDP: Fuzz L4 headers (ports, flags, etc.)")
    print("   • Application: Fuzz application payloads")
    print()
    
    print("📊 Response Analysis:")
    print("   • Capture responses with timeout control")
    print("   • Analyze response patterns and sizes")
    print("   • Detect error conditions and anomalies")
    print("   • Save results to new PCAP files")
    print()
    
    print("🎛️  Campaign Customization:")
    print("   • Custom target addresses per packet")
    print("   • Rate limiting and timing control")
    print("   • Callback functions for custom logic")
    print("   • Integration with existing campaign framework")
    print()
    
    print("=== Demo Complete ===")
    print()
    print("Key PCAP fuzzing capabilities:")
    print("• Load existing network captures for analysis")
    print("• Extract and fuzz specific protocol layers")
    print("• Multiple fuzzing modes (regression, field, binary, combined)")
    print("• Layer-specific targeting (L2, L3, L4, Application)")
    print("• Response capture and analysis")
    print("• Integration with dictionary-based fuzzing")
    print()
    print("To use PCAP fuzzing in your campaigns:")
    print("1. Inherit from PcapFuzzCampaign instead of FuzzingCampaign")
    print("2. Set pcap_file to your capture file")
    print("3. Choose fuzz_mode: 'none', 'field', 'binary', or 'both'")
    print("4. Optionally specify target_layer for layer-specific fuzzing")

if __name__ == "__main__":
    interactive_demo()
