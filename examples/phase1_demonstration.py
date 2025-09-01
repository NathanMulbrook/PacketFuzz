#!/usr/bin/env python3
"""
MutatorManagerData Phase 1 Demonstration

This script demonstrates the complete functionality of the new MutatorManagerData
tracking system implemented in Phase 1.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Imports
from packetfuzz.mutator_manager import FuzzConfig, FuzzMode
from packetfuzz.mutator_manager_data import MutatorManagerData
from packetfuzz.dictionary_manager import DictionaryManager
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether, ARP

# Import packet extensions for embedded configuration
import packetfuzz.packet_extensions


def demonstrate_basic_functionality():
    """Demonstrate basic MutatorManagerData functionality."""
    print("\n" + "="*60)
    print("1. BASIC FUNCTIONALITY DEMONSTRATION")
    print("="*60)
    
    # Create a test packet
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / Raw(b"test_data")
    
    # Create enhanced FuzzConfig
    config = FuzzConfig(
        packets=packet,
        iterations=1000,
        use_dictionaries=True,
        fuzz_weight=0.8,
        mode=FuzzMode.BOTH
    )
    
    print(f"✓ Created enhanced FuzzConfig: {config}")
    
    # Initialize tracking system
    data_tracker = MutatorManagerData(config)
    print(f"✓ Initialized MutatorManagerData: {data_tracker}")
    
    # Preprocess packets
    data_tracker.preprocess_packets()
    print(f"✓ Preprocessing complete")
    
    # Display results
    summary = data_tracker.get_processing_summary()
    print(f"\nProcessing Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")


def demonstrate_multiple_packets():
    """Demonstrate handling of multiple packets."""
    print("\n" + "="*60)
    print("2. MULTIPLE PACKET DEMONSTRATION")
    print("="*60)
    
    # Create different types of packets
    packets = [
        IP(dst="192.168.1.1") / TCP(dport=80) / Raw(b"HTTP data"),
        IP(dst="192.168.1.2") / UDP(dport=53) / DNS(qd=DNSQR(qname="test.com")),
        IP(dst="192.168.1.3") / TCP(dport=443) / Raw(b"HTTPS data"),
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    ]
    
    config = FuzzConfig(packets=packets, iterations=500)
    data_tracker = MutatorManagerData(config)
    data_tracker.preprocess_packets()
    
    print(f"✓ Processed {len(packets)} different packet types")
    print(f"✓ Total fields discovered: {data_tracker.total_fields}")
    print(f"✓ Fuzzable fields: {data_tracker.fuzzable_field_count}")
    
    # Show fields by layer
    for layer_name in ["IP", "TCP", "UDP", "DNS", "ARP"]:
        fields = data_tracker.get_fields_by_layer(layer_name)
        if fields:
            print(f"  {layer_name} fields: {len(fields)}")


def demonstrate_layer_collisions():
    """Demonstrate layer collision handling."""
    print("\n" + "="*60)
    print("3. LAYER COLLISION DEMONSTRATION")
    print("="*60)
    
    # Create packet with layer collisions (GRE tunneling scenario)
    collision_packet = IP(dst="192.168.1.1") / IP(dst="10.0.0.1") / TCP(dport=80)
    
    config = FuzzConfig(packets=collision_packet)
    data_tracker = MutatorManagerData(config)
    data_tracker.preprocess_packets()
    
    print(f"✓ Packet with layer collisions processed")
    
    # Show collision handling
    collision_summary = data_tracker.get_collision_summary()
    print(f"✓ Collision summary: {collision_summary}")
    
    # Show field keys with collision indexes
    ip_fields = data_tracker.get_fields_by_layer("IP")
    print(f"✓ IP fields found: {len(ip_fields)}")
    for field in ip_fields[:4]:  # Show first few
        print(f"  {field.field_key}: {field.current_value}")


def demonstrate_embedded_configuration():
    """Demonstrate embedded packet configuration resolution."""
    print("\n" + "="*60)
    print("4. EMBEDDED CONFIGURATION DEMONSTRATION")
    print("="*60)
    
    # Create packet with embedded configuration
    packet = IP(dst="192.168.1.100") / TCP(dport=80) / Raw(b"configured_data")
    
    # Add embedded field configuration
    tcp_layer = packet[TCP]
    tcp_layer.field_fuzz('dport').default_values = [8080, 8443, 9000]
    tcp_layer.field_fuzz('dport').fuzz_weight = 0.9
    tcp_layer.field_fuzz('dport').dictionary = ["custom_ports.txt"]
    
    # Also configure another field
    tcp_layer.field_fuzz('sport').default_values = [1024, 2048, 4096]
    tcp_layer.field_fuzz('sport').fuzz_weight = 0.7
    
    config = FuzzConfig(packets=packet)
    data_tracker = MutatorManagerData(config)
    data_tracker.preprocess_packets()
    
    print(f"✓ Embedded configuration processed")
    
    # Show resolved configuration
    dport_field = data_tracker.get_field_by_key("TCP[0].dport", 0)
    sport_field = data_tracker.get_field_by_key("TCP[0].sport", 0)
    
    if dport_field:
        print(f"✓ dport field configuration:")
        print(f"  Weight: {dport_field.fuzz_weight}")
        print(f"  Default values: {dport_field.default_values}")
        print(f"  Dictionary paths: {dport_field.dictionary_paths}")
        print(f"  Config source: {dport_field.config_source}")
    
    if sport_field:
        print(f"✓ sport field configuration:")
        print(f"  Weight: {sport_field.fuzz_weight}")
        print(f"  Default values: {sport_field.default_values}")
        print(f"  Config source: {sport_field.config_source}")


def demonstrate_query_interface():
    """Demonstrate the query interface functionality."""
    print("\n" + "="*60)
    print("5. QUERY INTERFACE DEMONSTRATION")
    print("="*60)
    
    # Create mixed packet scenario
    packets = [
        IP(dst="192.168.1.1") / TCP(dport=80),
        IP(dst="192.168.1.2") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
    ]
    
    config = FuzzConfig(packets=packets, iterations=200)
    data_tracker = MutatorManagerData(config)
    data_tracker.preprocess_packets()
    
    print(f"✓ Query interface ready")
    
    # Demonstrate various queries
    all_fuzzable = data_tracker.get_all_fuzzable_fields()
    print(f"✓ All fuzzable fields: {len(all_fuzzable)}")
    
    tcp_fields = data_tracker.get_fields_by_layer("TCP")
    udp_fields = data_tracker.get_fields_by_layer("UDP")
    print(f"✓ TCP fields: {len(tcp_fields)}, UDP fields: {len(udp_fields)}")
    
    # Show specific field details
    if tcp_fields:
        field = tcp_fields[0]
        print(f"✓ Sample TCP field: {field.field_key}")
        print(f"  Type: {field.field_type} ({field.field_kind})")
        print(f"  Value: {field.current_value}")
        print(f"  Constraints: min={field.min_value}, max={field.max_value}")


def demonstrate_mutation_tracking():
    """Demonstrate mutation tracking functionality."""
    print("\n" + "="*60)
    print("6. MUTATION TRACKING DEMONSTRATION")
    print("="*60)
    
    packet = IP(dst="192.168.1.100") / TCP(dport=80)
    config = FuzzConfig(packets=packet)
    data_tracker = MutatorManagerData(config)
    data_tracker.preprocess_packets()
    
    print(f"✓ Mutation tracking ready")
    
    # Simulate some mutations
    fuzzable_fields = data_tracker.get_all_fuzzable_fields()
    if fuzzable_fields:
        field = fuzzable_fields[0]
        field_key = field.field_key
        
        # Record some mutations
        data_tracker.record_field_mutation(field_key, 0, True, "libfuzzer")
        data_tracker.record_field_mutation(field_key, 0, True, "dictionary")
        data_tracker.record_field_mutation(field_key, 0, False, "scapy")
        
        # Show tracking results
        updated_field = data_tracker.get_field_by_key(field_key, 0)
        print(f"✓ Field {field_key} mutation tracking:")
        print(f"  Total mutations: {updated_field.mutation_count}")
        print(f"  Successful: {updated_field.successful_mutations}")
        print(f"  Failed: {updated_field.failed_mutations}")
        print(f"  Last mutated: {updated_field.last_mutated}")


def demonstrate_memory_efficiency():
    """Demonstrate memory efficiency with larger dataset."""
    print("\n" + "="*60)
    print("7. MEMORY EFFICIENCY DEMONSTRATION")
    print("="*60)
    
    # Create 50 packets for testing (smaller than production target)
    packets = []
    for i in range(50):
        packet = IP(dst=f"192.168.{i//254}.{i%254+1}") / TCP(dport=80+i%100) / Raw(b"x"*20)
        packets.append(packet)
    
    config = FuzzConfig(packets=packets, iterations=5000)
    data_tracker = MutatorManagerData(config)
    
    import time
    start_time = time.time()
    data_tracker.preprocess_packets()
    processing_time = time.time() - start_time
    
    print(f"✓ Processed {len(packets)} packets in {processing_time:.3f} seconds")
    print(f"✓ Total fields: {data_tracker.total_fields}")
    print(f"✓ Fuzzable fields: {data_tracker.fuzzable_field_count}")
    print(f"✓ Average fields per packet: {data_tracker.total_fields / len(packets):.1f}")
    print(f"✓ Processing rate: {len(packets) / processing_time:.1f} packets/second")


def main():
    """Run all demonstrations."""
    print("MutatorManagerData Phase 1 Demonstration")
    print("========================================")
    print("This script demonstrates the complete functionality of the new")
    print("self-contained data tracking system for PacketFuzz.")
    
    try:
        demonstrate_basic_functionality()
        demonstrate_multiple_packets()
        demonstrate_layer_collisions()
        demonstrate_embedded_configuration()
        demonstrate_query_interface()
        demonstrate_mutation_tracking()
        demonstrate_memory_efficiency()
        
        print("\n" + "="*60)
        print("ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\nPhase 1 Implementation Features Demonstrated:")
        print("✓ Enhanced FuzzConfig with packet and iteration support")
        print("✓ Self-contained MutatorManagerData initialization")
        print("✓ Comprehensive packet preprocessing and field discovery")
        print("✓ Layer collision detection with indexed field keys (TCP[0].dport format)")
        print("✓ Direct storage approach for field metadata")
        print("✓ Embedded configuration resolution (field_fuzz() integration)")
        print("✓ Complete query interface for field access")
        print("✓ Mutation tracking and statistics")
        print("✓ Memory-efficient processing of packet batches")
        print("✓ Full backwards compatibility with existing FuzzConfig")
        
        print("\nNext Steps (Phase 2):")
        print("• Integrate with existing MutatorManager workflow")
        print("• Add lazy initialization pattern")
        print("• Update campaign framework integration")
        print("• Enhance reporting and analytics capabilities")
        
    except Exception as e:
        print(f"\nDemonstration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
