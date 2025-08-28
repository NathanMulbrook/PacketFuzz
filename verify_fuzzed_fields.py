#!/usr/bin/env python3
"""
Verify that fuzzed fields are correctly tracked per packet.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scapy.all import *
from packetfuzz.fuzzing_framework import FuzzingFramework
from packetfuzz.mutator_manager import MutatorManager

def test_specific_field_tracking():
    """Test that specific fields are correctly tracked when fuzzed."""
    
    # Create a simple packet with FuzzField
    packet = Ether() / IP(dst="192.168.1.1") / TCP(dport=FuzzField(values=[80, 443, 8080])) / Raw(load="test data")
    
    # Create framework and manager
    framework = FuzzingFramework(
        target="192.168.1.1",
        iterations=2,
        mutation_parameters={'FORCE_FUZZ': ['TCP.dport']},  # Force fuzz only TCP.dport
        save_pcap=False
    )
    
    # Create a list to track what gets fuzzed
    fuzzed_tracking = []
    
    # Override the send method to capture fuzzed fields
    original_send = framework.send_packet
    def capture_send(packet, iteration):
        # Get the fuzzed fields from the current iteration
        if hasattr(framework.mutator_manager, 'fuzzed_fields_per_packet') and iteration < len(framework.mutator_manager.fuzzed_fields_per_packet):
            fuzzed_fields = framework.mutator_manager.fuzzed_fields_per_packet[iteration]
            fuzzed_tracking.append(fuzzed_fields)
            print(f"Iteration {iteration}: Fuzzed fields = {fuzzed_fields}")
        return original_send(packet, iteration)
    
    framework.send_packet = capture_send
    
    # Run the campaign
    print("=== TESTING SPECIFIC FIELD TRACKING ===")
    print(f"Original packet: {packet}")
    
    result = framework.fuzz(packet)
    
    print(f"\nResult: {result}")
    print(f"Captured fuzzed fields: {fuzzed_tracking}")
    
    # Verify that TCP.dport was fuzzed in each iteration
    for i, fields in enumerate(fuzzed_tracking):
        if 'TCP.dport' not in fields:
            print(f"ERROR: TCP.dport was NOT fuzzed in iteration {i}, fields: {fields}")
        else:
            print(f"SUCCESS: TCP.dport was fuzzed in iteration {i}")

if __name__ == "__main__":
    test_specific_field_tracking()
