#!/usr/bin/env python3
"""
Comprehensive validation of layer weight scaling functionality.
This script validates scaling behavior across different field types and scenarios.
"""

import sys
from pathlib import Path
# Add the root project directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import tempfile
import os
from collections import defaultdict
from scapy.all import *
from fuzzing_framework import FuzzingCampaign
import logging

logging.getLogger('scapy').setLevel(logging.WARNING)

class ComprehensiveScalingTestCampaign(FuzzingCampaign):
    """Campaign for comprehensive layer weight scaling validation"""
    
    def __init__(self, scaling_factor: float, packet_template, test_name: str):
        super().__init__()
        self.layer_weight_scaling = scaling_factor
        self.enable_layer_weight_scaling = True
        self.iterations = 300  # More samples for better statistics
        self.duration = None
        self.target = "192.168.1.100"  # Match packet dst to avoid override
        self.target_port = 8080
        self.rate_limit = 1000
        self.send_packets = True
        self.output_network = False
        self.verbose = False
        self.packet_template = packet_template
        self.test_name = test_name
        
        # Create temp file for output
        self.temp_file = tempfile.NamedTemporaryFile(suffix=f'_{test_name}_{scaling_factor}.pcap', delete=False)
        self.output_pcap = self.temp_file.name
        self.temp_file.close()
        
    def get_packet(self):
        """Return the packet template"""
        return self.packet_template.copy()
    
    def cleanup(self):
        """Clean up temp file"""
        if os.path.exists(self.output_pcap):
            os.unlink(self.output_pcap)

def analyze_field_mutations(original_packet, pcap_file, fields_to_track):
    """Analyze specific field mutation rates"""
    if not os.path.exists(pcap_file):
        return {}
    
    packets = rdpcap(pcap_file)
    stats = {}
    
    for field_path in fields_to_track:
        layer_name, field_name = field_path.split('.')
        mutations = 0
        total = 0
        
        # Get original value
        if layer_name == 'IP':
            if IP in original_packet:
                original_value = str(getattr(original_packet[IP], field_name))
            else:
                continue
        elif layer_name == 'TCP':
            if TCP in original_packet:
                original_value = str(getattr(original_packet[TCP], field_name))
            else:
                continue
        elif layer_name == 'UDP':
            if UDP in original_packet:
                original_value = str(getattr(original_packet[UDP], field_name))
            else:
                continue
        else:
            continue
            
        # Count mutations
        for pkt in packets:
            if layer_name == 'IP' and IP in pkt:
                current_value = str(getattr(pkt[IP], field_name))
                if current_value != original_value:
                    mutations += 1
                total += 1
            elif layer_name == 'TCP' and TCP in pkt:
                current_value = str(getattr(pkt[TCP], field_name))
                if current_value != original_value:
                    mutations += 1
                total += 1
            elif layer_name == 'UDP' and UDP in pkt:
                current_value = str(getattr(pkt[UDP], field_name))
                if current_value != original_value:
                    mutations += 1
                total += 1
        
        if total > 0:
            stats[field_path] = {
                'mutations': mutations,
                'total': total,
                'rate': (mutations / total) * 100
            }
        else:
            stats[field_path] = {'mutations': 0, 'total': 0, 'rate': 0.0}
    
    return stats

def test_scenario(scenario_name, packet_template, fields_to_track, expected_behavior):
    """Test a specific scaling scenario"""
    print(f"\n{'='*80}")
    print(f"TESTING SCENARIO: {scenario_name}")
    print(f"{'='*80}")
    print(f"Packet: {packet_template.summary()}")
    print(f"Fields to track: {fields_to_track}")
    
    results = {}
    campaigns = []
    
    try:
        # Test both scaling factors
        for scaling in [0.9, 0.1]:
            print(f"\n--- Testing scaling factor: {scaling} ---")
            
            campaign = ComprehensiveScalingTestCampaign(scaling, packet_template, scenario_name)
            campaigns.append(campaign)
            
            success = campaign.execute()
            if not success:
                print(f"Campaign failed for scaling {scaling}")
                continue
                
            # Analyze results
            stats = analyze_field_mutations(packet_template, campaign.output_pcap, fields_to_track)
            results[scaling] = stats
            
            print(f"Results for scaling {scaling}:")
            for field, data in stats.items():
                print(f"  {field}: {data['mutations']}/{data['total']} = {data['rate']:.1f}%")
        
        # Compare results
        print(f"\n--- COMPARISON FOR {scenario_name} ---")
        if 0.9 in results and 0.1 in results:
            working_fields = []
            broken_fields = []
            zero_mutation_fields = []
            
            for field in fields_to_track:
                if field in results[0.9] and field in results[0.1]:
                    rate_09 = results[0.9][field]['rate']
                    rate_01 = results[0.1][field]['rate']
                    diff = rate_09 - rate_01
                    
                    print(f"{field:>15}: {rate_09:6.1f}% -> {rate_01:6.1f}% (diff: {diff:+6.1f}%)")
                    
                    # Categorize field behavior
                    if rate_09 == 0 and rate_01 == 0:
                        zero_mutation_fields.append(field)
                    elif diff > 5.0:  # Significant positive difference (correct behavior)
                        working_fields.append(field)
                    elif diff < -2.0:  # Negative difference (inverted behavior)
                        broken_fields.append(field)
                    else:  # Small difference (edge case)
                        broken_fields.append(field)
            
            print(f"\nField Classification:")
            print(f"  Working correctly: {working_fields}")
            print(f"  Zero mutations: {zero_mutation_fields}")
            print(f"  Anomalous behavior: {broken_fields}")
            
            return {
                'working_fields': working_fields,
                'zero_mutation_fields': zero_mutation_fields,
                'broken_fields': broken_fields,
                'detailed_results': results
            }
        else:
            print("Failed to get results for both scaling factors")
            return None
            
    finally:
        # Cleanup
        for campaign in campaigns:
            campaign.cleanup()

def main():
    """Run comprehensive validation tests"""
    print("COMPREHENSIVE LAYER WEIGHT SCALING VALIDATION")
    print("=" * 80)
    
    test_scenarios = [
        {
            'name': 'Basic TCP Packet',
            'packet': IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=12345, dport=80, seq=1000),
            'fields': ['IP.src', 'IP.dst', 'IP.ttl', 'TCP.sport', 'TCP.dport', 'TCP.seq'],
            'expected': 'TCP fields should show strong scaling, IP.ttl should scale, IP.src/dst may have edge cases'
        },
        {
            'name': 'Basic UDP Packet', 
            'packet': IP(src='10.0.0.1', dst='192.168.1.100') / UDP(sport=12345, dport=53),
            'fields': ['IP.src', 'IP.dst', 'IP.ttl', 'UDP.sport', 'UDP.dport'],
            'expected': 'UDP fields should show strong scaling, IP.ttl should scale'
        },
        {
            'name': 'Multi-layer TCP with Payload',
            'packet': IP(src='10.0.0.1', dst='192.168.1.100') / TCP(sport=12345, dport=80) / Raw(b"test"),
            'fields': ['IP.src', 'IP.dst', 'IP.ttl', 'TCP.sport', 'TCP.dport', 'TCP.seq'],
            'expected': 'Similar to basic TCP but with Raw layer affecting probabilities'
        },
        {
            'name': 'Different IP Addresses',
            'packet': IP(src='172.16.1.1', dst='203.0.113.1') / TCP(sport=443, dport=22),
            'fields': ['IP.src', 'IP.dst', 'IP.ttl', 'TCP.sport', 'TCP.dport'],
            'expected': 'Check if different IPs affect the behavior'
        }
    ]
    
    all_results = {}
    
    for scenario in test_scenarios:
        result = test_scenario(
            scenario['name'],
            scenario['packet'], 
            scenario['fields'],
            scenario['expected']
        )
        all_results[scenario['name']] = result
    
    # Summary
    print(f"\n{'='*80}")
    print("OVERALL SUMMARY")
    print(f"{'='*80}")
    
    all_working = set()
    all_zero = set()
    all_broken = set()
    
    for scenario_name, result in all_results.items():
        if result:
            print(f"\n{scenario_name}:")
            print(f"  Working: {result['working_fields']}")
            print(f"  Zero mutations: {result['zero_mutation_fields']}")
            print(f"  Anomalous: {result['broken_fields']}")
            
            all_working.update(result['working_fields'])
            all_zero.update(result['zero_mutation_fields'])
            all_broken.update(result['broken_fields'])
    
    print(f"\nCONSOLIDATED RESULTS:")
    print(f"  Consistently working fields: {sorted(all_working - all_broken)}")
    print(f"  Consistently zero mutation fields: {sorted(all_zero)}")
    print(f"  Fields with anomalous behavior: {sorted(all_broken)}")
    
    # Determine if core scaling works
    core_tcp_fields = ['TCP.sport', 'TCP.dport', 'TCP.seq']
    core_udp_fields = ['UDP.sport', 'UDP.dport']
    working_core_tcp = set(core_tcp_fields) & (all_working - all_broken)
    working_core_udp = set(core_udp_fields) & (all_working - all_broken)
    
    print(f"\nCORE FUNCTIONALITY ASSESSMENT:")
    print(f"  TCP core fields working: {sorted(working_core_tcp)} / {core_tcp_fields}")
    print(f"  UDP core fields working: {sorted(working_core_udp)} / {core_udp_fields}")
    
    if len(working_core_tcp) >= 2 or len(working_core_udp) >= 1:
        print(f"  [PASS] CORE LAYER WEIGHT SCALING IS WORKING")
        print(f"     Lower scaling factors produce significantly fewer mutations in outer layers")
    else:
        print(f"  [FAIL] CORE LAYER WEIGHT SCALING HAS ISSUES")
        
    return all_results

if __name__ == '__main__':
    main()
