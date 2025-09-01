#!/usr/bin/env python3
"""
Demo of MutatorManagerData integration with FuzzingCampaign
"""

from scapy.all import IP, TCP, Raw
from packetfuzz.fuzzing_framework import FuzzingCampaign

class DemoCampaign(FuzzingCampaign):
    def get_packet(self):
        return IP(dst="127.0.0.1")/TCP(dport=80)/Raw(b"test data")

def demo_mutator_data_integration():
    """Demonstrate the rich data available from MutatorManagerData"""
    print("🔧 PacketFuzz MutatorManagerData Integration Demo")
    print("=" * 60)
    
    campaign = DemoCampaign()
    
    # Create fuzzer (this now stores MutatorManagerData in campaign)
    print("Creating fuzzer and preprocessing packets...")
    fuzzer = campaign.create_fuzzer()
    
    # Access the rich data through the campaign
    data = campaign.get_mutator_data()
    
    print(f"\n📊 Preprocessing Results:")
    print(f"  Total packets: {data.total_packets}")
    print(f"  Total fields discovered: {data.total_fields}")
    print(f"  Fuzzable fields: {len([f for pd in data.packet_data for f in pd.fields.values() if f.is_fuzzable])}")
    print(f"  Excluded fields: {len([f for pd in data.packet_data for f in pd.fields.values() if not f.is_fuzzable])}")
    
    print(f"\n🔍 Field Types Discovered:")
    field_types = data.get_all_fieldtypes()
    for i, field_type in enumerate(sorted(field_types)[:10]):  # Show first 10
        print(f"  {i+1:2d}. {field_type}")
    if len(field_types) > 10:
        print(f"     ... and {len(field_types) - 10} more")
    
    print(f"\n🎯 Layer Analysis:")
    packet_data = data.packet_data[0]  # First packet
    layers = {}
    for field_metadata in packet_data.fields.values():
        layer = field_metadata.layer_name
        if layer not in layers:
            layers[layer] = []
        layers[layer].append(field_metadata.field_name)
    
    for layer_name, fields in layers.items():
        print(f"  {layer_name}: {len(fields)} fields")
        example_fields = fields[:3]  # Show first 3 fields
        print(f"    Examples: {', '.join(example_fields)}")
        if len(fields) > 3:
            print(f"    ... and {len(fields) - 3} more")
    
    print(f"\n⚙️  Configuration Sources:")
    config_sources = {}
    for field_metadata in packet_data.fields.values():
        source = field_metadata.config_source
        config_sources[source] = config_sources.get(source, 0) + 1
    
    for source, count in config_sources.items():
        print(f"  {source}: {count} fields")
    
    # Demonstrate mutation tracking
    print(f"\n🔄 Testing Mutation Tracking:")
    test_packets = fuzzer.fuzz_packet(campaign.get_packet(), iterations=3)
    print(f"  Generated {len(test_packets)} mutated packets")
    
    # Show field usage summary
    usage_summary = fuzzer.get_mutator_usage_counts()
    if usage_summary:
        print(f"  Mutator usage: {dict(list(usage_summary.items())[:3])}")
    
    print(f"\n✅ Integration working perfectly!")
    print(f"   Campaign now has access to rich field metadata and tracking!")

if __name__ == "__main__":
    demo_mutator_data_integration()
