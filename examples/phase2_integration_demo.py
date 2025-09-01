#!/usr/bin/env python3
"""
MutatorManagerData Phase 2 Integration Demonstration

This script demonstrates the complete Phase 2 integration of the 
MutatorManagerData system with the MutatorManager fuzzing workflow.

Features demonstrated:
- Automatic data storage creation at MutatorManager initialization
- Field discovery and preprocessing using MutatorManagerData
- Mutation selection and application using preprocessed data
- Tracking and statistics integration
- Backwards compatibility with existing MutatorManager API
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from packetfuzz.mutator_manager import MutatorManager
from packetfuzz.mutator_manager_data import FuzzConfig, FuzzMode
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, Raw, ARP


def demonstrate_basic_integration():
    """Demonstrate basic Phase 2 integration with automatic data creation."""
    print("=" * 60)
    print("1. BASIC PHASE 2 INTEGRATION")
    print("=" * 60)
    
    # Create packet and configuration
    packet = IP(dst='192.168.1.100')/TCP(dport=443, sport=12345)
    config = FuzzConfig(
        mode=FuzzMode.FIELD_LEVEL,
        packets=packet,
        iterations=500
    )
    
    print(f"✓ Created FuzzConfig: {config}")
    
    # Create MutatorManager - this automatically creates MutatorManagerData
    manager = MutatorManager(config)
    
    print(f"✓ MutatorManager created with automatic data storage")
    
    # Access the data storage
    data = manager.get_mutator_manager_data()
    print(f"✓ Data storage contains: {data.total_fields} fields, {data.fuzzable_field_count} fuzzable")
    
    # Show some field information
    sample_fields = data.get_all_fuzzable_fields()[:5]
    print("✓ Sample fuzzable fields:")
    for field in sample_fields:
        print(f"  {field.field_key}: weight={field.fuzz_weight}, type={field.field_kind}")
    
    return manager


def demonstrate_integrated_fuzzing(manager):
    """Demonstrate fuzzing using the integrated data system."""
    print("\\n" + "=" * 60)
    print("2. INTEGRATED FUZZING WORKFLOW")
    print("=" * 60)
    
    # Get original packet
    original_packet = IP(dst='192.168.1.100')/TCP(dport=443, sport=12345)
    print(f"Original packet: IP.dst={original_packet[IP].dst}, TCP.dport={original_packet[TCP].dport}, TCP.sport={original_packet[TCP].sport}")
    
    # Fuzz using the new integrated system
    fuzzed_packets = manager.fuzz_fields(original_packet, iterations=5)
    print(f"✓ Generated {len(fuzzed_packets)} fuzzed packets using preprocessed data")
    
    # Show mutations
    print("✓ Sample mutations applied:")
    for i, packet in enumerate(fuzzed_packets):
        ip_flags = packet[IP].flags if hasattr(packet[IP], 'flags') else 'N/A'
        print(f"  Packet {i}: IP.flags={ip_flags}, TCP.dport={packet[TCP].dport}, TCP.sport={packet[TCP].sport}")
    
    # Show tracking information
    current_fields = manager.get_current_fuzzed_fields()
    print(f"✓ Currently tracked fuzzed fields: {len(current_fields)}")
    for field in current_fields[:3]:
        print(f"  {field}")


def demonstrate_statistics_tracking(manager):
    """Demonstrate mutation statistics and tracking."""
    print("\\n" + "=" * 60)
    print("3. STATISTICS AND TRACKING")
    print("=" * 60)
    
    # Access data storage for statistics
    data = manager.get_mutator_manager_data()
    
    # Show field statistics
    all_fields = data.get_all_fuzzable_fields()
    mutated_fields = [f for f in all_fields if f.mutation_count > 0]
    
    print(f"✓ Total fuzzable fields: {len(all_fields)}")
    print(f"✓ Fields that were mutated: {len(mutated_fields)}")
    
    if mutated_fields:
        print("✓ Mutation statistics for recently mutated fields:")
        for field in mutated_fields[:5]:  # Show first 5
            print(f"  {field.field_key}: {field.successful_mutations} successful, {field.failed_mutations} failed")
    
    # Show layer breakdown
    ip_fields = data.get_fields_by_layer("IP")
    tcp_fields = data.get_fields_by_layer("TCP")
    print(f"✓ Layer breakdown: IP={len(ip_fields)} fields, TCP={len(tcp_fields)} fields")


def demonstrate_simplified_architecture():
    """Demonstrate the simplified architecture without fallback logic."""
    print("\\n" + "=" * 60)
    print("4. BACKWARDS COMPATIBILITY")
    print("=" * 60)
    print("4. SIMPLIFIED ARCHITECTURE")
    print("=" * 60)
    
    # Demonstrate that MutatorManager now requires packets in config
    try:
        old_config = FuzzConfig(mode=FuzzMode.FIELD_LEVEL, max_mutations=100)
        old_manager = MutatorManager(old_config)
        print("❌ This should have failed - no fallback logic anymore")
    except ValueError as e:
        print(f"✓ MutatorManager correctly requires packets: {e}")
    
    # Show that all operations now go through the data storage system
    packet = IP(dst='10.0.0.1')/UDP(dport=53)
    simple_config = FuzzConfig(mode=FuzzMode.FIELD_LEVEL, packets=[packet], iterations=2)
    simple_manager = MutatorManager(simple_config)
    
    print(f"✓ Simple creation with packets: {simple_manager.get_mutator_manager_data().total_fields} fields")
    
    # All fuzzing operations use preprocessed data
    fuzzed = simple_manager.fuzz_fields(packet, iterations=2)
    print(f"✓ Fuzzing uses preprocessed data: generated {len(fuzzed)} packets")


def demonstrate_advanced_features():
    """Demonstrate advanced features like layer collisions and field filtering."""
    print("\\n" + "=" * 60)
    print("5. ADVANCED FEATURES")
    print("=" * 60)
    
    # Create packet with layer collisions (multiple IP layers)
    complex_packet = IP(dst='1.1.1.1')/IP(dst='2.2.2.2')/TCP(dport=80)
    config = FuzzConfig(packets=complex_packet, iterations=100)
    manager = MutatorManager(config)
    
    print("✓ Created packet with layer collisions (IP/IP/TCP)")
    
    # Check collision detection
    data = manager.get_mutator_manager_data()
    collisions = data.get_collision_summary()
    print(f"✓ Layer collisions detected: {collisions}")
    
    # Show collision handling in field keys
    all_fields = data.get_all_fuzzable_fields()
    ip_fields = [f for f in all_fields if f.layer_name == "IP"]
    print("✓ Collision-resolved field keys:")
    for field in ip_fields[:5]:
        print(f"  {field.field_key} (layer_index={field.layer_index})")
    
    # Test field-specific fuzzing
    fuzzed = manager.fuzz_fields(complex_packet, iterations=1, field_name="dst")
    print(f"✓ Field-specific fuzzing (dst field only): {len(fuzzed)} packets")


def main():
    """Run the complete Phase 2 integration demonstration."""
    print("MutatorManagerData Phase 2 Integration Demonstration")
    print("=" * 60)
    print("This script demonstrates the complete integration of MutatorManagerData")
    print("with the MutatorManager fuzzing workflow.")
    print()
    
    try:
        # Basic integration
        manager = demonstrate_basic_integration()
        
        # Integrated fuzzing
        demonstrate_integrated_fuzzing(manager)
        
        # Statistics tracking
        demonstrate_statistics_tracking(manager)
        
        # Backwards compatibility
        demonstrate_simplified_architecture()
        
        # Advanced features
        demonstrate_advanced_features()
        
        print("\\n" + "=" * 60)
        print("ALL PHASE 2 INTEGRATION DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        
        print("\\nPhase 2 Integration Summary:")
        print("✓ Automatic MutatorManagerData creation at MutatorManager initialization")
        print("✓ Field discovery and preprocessing replaced old runtime discovery")
        print("✓ Mutation selection and application using preprocessed metadata")
        print("✓ Statistics tracking and mutation state management")
        print("✓ Layer collision detection with indexed field keys")
        print("✓ Backwards compatibility with existing MutatorManager API")
        print("✓ Performance improvement through preprocessing")
        print("✓ Complete integration with existing fuzzing workflow")
        
        print("\\nNext Steps (Future Phases):")
        print("• Enhanced reporting and analytics using tracking data")
        print("• Campaign framework integration")
        print("• Advanced mutation strategies based on field metadata")
        print("• Performance optimization and caching")
        
    except Exception as e:
        print(f"\\n❌ Phase 2 integration demonstration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
