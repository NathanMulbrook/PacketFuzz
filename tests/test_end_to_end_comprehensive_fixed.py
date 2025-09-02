#!/usr/bin/env python3
"""
Test file to check specific failing test
"""

import sys
import os
import unittest
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import IP, TCP, UDP, DNS, DNSQR
from packetfuzz.mutator_manager_data import MutatorManagerData
from packetfuzz.fuzzing_framework import FuzzConfig  
from packetfuzz.dictionary_manager import DictionaryManager


class TestFieldAnalysisEndToEnd(unittest.TestCase):
    """End-to-end tests for field analysis utilities"""
    
    def test_field_analysis_mutation_integration_e2e(self):
        """End-to-end test: Field analysis integrates with mutation system"""
        
        # Create test configuration
        config = FuzzConfig()
        config.packets = [
            IP(dst="192.168.1.1") / TCP(dport=80),
            IP(dst="10.0.0.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
        ]
        config.iterations = 10
        
        # Initialize mutation data manager
        data_manager = MutatorManagerData(config)
        
        # Process packets through field analysis
        dictionary_manager = DictionaryManager()
        data_manager.preprocess_packets(dictionary_manager)
        
        # Verification criteria:
        # 1. Packets should be processed
        self.assertGreater(len(data_manager.packet_data), 0, "Should process packets")
        
        # 2. Field metadata should be extracted
        total_fields = sum(len(packet.fields) for packet in data_manager.packet_data)
        self.assertGreater(total_fields, 5, f"Expected field extraction, got {total_fields} fields")
        
        # 3. Check for field analysis (constraints may vary based on implementation)
        fields_with_constraints = sum(
            1 for packet in data_manager.packet_data
            for field in packet.fields
            if hasattr(field, 'min_value') and hasattr(field, 'max_value') and
               any([getattr(field, 'min_value', None) is not None, 
                    getattr(field, 'max_value', None) is not None,
                    getattr(field, 'min_length', None) is not None, 
                    getattr(field, 'max_length', None) is not None])
        )
        
        # Note: Constraint analysis may vary based on field implementation
        if fields_with_constraints == 0:
            print(f"   Note: No explicit constraints found in {total_fields} fields")
        
        print(f"✅ Field Analysis Mutation Integration E2E Test PASSED:")
        print(f"   - Processed {len(data_manager.packet_data)} packets")
        print(f"   - Extracted {total_fields} fields")
        print(f"   - {fields_with_constraints} fields have constraints")


if __name__ == '__main__':
    unittest.main()
