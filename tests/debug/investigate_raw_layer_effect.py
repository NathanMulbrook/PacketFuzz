#!/usr/bin/env python3
"""
Investigation into why Raw layer presence affects scaling behavior
"""

from pathlib import Path
import sys
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from packetfuzz.fuzzing_framework import FuzzConfig
from packetfuzz.mutator_manager import MutatorManager
from scapy.layers.inet import IP, TCP
from scapy.all import *
import random

def investigate_raw_layer_effect():
    """Investigate why Raw layer affects scaling behavior"""
    
    print("INVESTIGATING RAW LAYER EFFECT ON SCALING")
    print("=" * 60)
    
    # Create two similar packets - one with Raw, one without
    packet_no_raw = IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=12345, dport=80, seq=1000)
    packet_with_raw = IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=12345, dport=80, seq=1000) / Raw(b"test")
    
    print(f"Packet without Raw: {packet_no_raw.summary()}")
    print(f"Packet with Raw: {packet_with_raw.summary()}")
    
    # Test scaling for both packets
    for scaling in [0.9, 0.1]:
        print(f"\n--- Testing scaling factor: {scaling} ---")
        
        config = FuzzConfig()
        config.layer_weight_scaling = scaling
        mm = MutatorManager(config)
        dm = mm.dictionary_manager
        
        for packet_name, packet in [("No Raw", packet_no_raw), ("With Raw", packet_with_raw)]:
            print(f"\n{packet_name} packet:")
            
            # Test TCP.sport field specifically
            tcp_layer = packet[TCP]
            field_name = 'sport'
            
            # Calculate effective weight
            base_weight = dm.get_field_weight(tcp_layer, field_name)
            depth = 1  # TCP is at depth 1 (after IP)
            effective_weight = base_weight * (scaling ** depth)
            
            print(f"  Base weight: {base_weight}")
            print(f"  Depth: {depth}")
            print(f"  Effective weight: {effective_weight}")
            
            # Test skip probability
            skip_count = 0
            total_tests = 1000
            
            random.seed(42)  # For reproducible results
            for i in range(total_tests):
                should_skip = mm._should_skip_field(tcp_layer, field_name)
                if should_skip:
                    skip_count += 1
            
            skip_rate = (skip_count / total_tests) * 100
            mutation_rate = 100 - skip_rate
            
            print(f"  Skip rate: {skip_rate:.1f}%")
            print(f"  Theoretical mutation rate: {mutation_rate:.1f}%")

def investigate_packet_structure_depth():
    """Investigate how packet structure affects depth calculations"""
    
    print("\n" + "=" * 60)
    print("INVESTIGATING PACKET DEPTH CALCULATIONS")
    print("=" * 60)
    
    packets = [
        ("IP/TCP", IP()/TCP()),
        ("IP/TCP/Raw", IP()/TCP()/Raw(b"test")),
        ("IP/UDP", IP()/UDP()),
        ("IP/UDP/Raw", IP()/UDP()/Raw(b"test")),
    ]
    
    config = FuzzConfig()
    config.layer_weight_scaling = 0.1
    mm = MutatorManager(config)
    
    for name, packet in packets:
        print(f"\n{name}:")
        print(f"  Packet: {packet.summary()}")
        print(f"  Layers: {[layer.__class__.__name__ for layer in packet.layers()]}")
        
        # Check depth calculation for each layer
        for i, layer in enumerate(packet.layers()):
            layer_obj = packet.getlayer(i)
            print(f"    Layer {i}: {layer.__name__} - {layer_obj}")

if __name__ == '__main__':
    investigate_raw_layer_effect()
    investigate_packet_structure_depth()
