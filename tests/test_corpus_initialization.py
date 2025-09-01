#!/usr/bin/env python3
"""
Test corpus initialization functionality for mutators.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from collections import namedtuple

from packetfuzz.mutators.libfuzzer_mutator import LibFuzzerMutator
from packetfuzz.mutators.dictionary_only_mutator import DictionaryOnlyMutator
from packetfuzz.mutators.scapy_mutator import ScapyMutator
from packetfuzz.mutator_manager import MutatorManager, FuzzConfig


class TestCorpusInitialization(unittest.TestCase):
    """Test corpus initialization and teardown functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a simple field info object
        self.FieldInfo = namedtuple('FieldInfo', ['name', 'kind', 'min_value', 'max_value', 'max_length'])
        self.string_field = self.FieldInfo('test_string', 'string', None, None, 100)
        self.numeric_field = self.FieldInfo('test_number', 'numeric', 0, 1000, None)
        self.raw_field = self.FieldInfo('test_raw', 'raw', None, None, None)
        
        self.seed_data = ['hello', 'world', 'test', b'binary_data', 42, 'longer_string_value']
    
    def test_libfuzzer_corpus_initialization(self):
        """Test LibFuzzer corpus initialization and teardown."""
        mutator = LibFuzzerMutator()
        
        try:
            # Test string field corpus initialization
            success = mutator.initialize(self.string_field, self.seed_data)
            self.assertIsInstance(success, bool)
            
            if mutator.is_libfuzzer_available():
                # LibFuzzer is available, should initialize successfully
                self.assertTrue(success, "Should initialize successfully when LibFuzzer is available")
            else:
                # LibFuzzer not available, initialization should fail gracefully
                self.assertFalse(success, "Should fail gracefully when LibFuzzer is not available")
            
            # Test numeric field corpus initialization
            numeric_success = mutator.initialize(self.numeric_field, self.seed_data)
            self.assertIsInstance(numeric_success, bool)
            
            if mutator.is_libfuzzer_available():
                self.assertTrue(numeric_success, "Numeric field initialization should succeed when LibFuzzer is available")
            
            # Test raw field corpus initialization
            raw_success = mutator.initialize(self.raw_field, self.seed_data)
            self.assertIsInstance(raw_success, bool)
            
            if mutator.is_libfuzzer_available():
                self.assertTrue(raw_success, "Raw field initialization should succeed when LibFuzzer is available")
        
        finally:
            # Test teardown
            teardown_success = mutator.teardown()
            self.assertIsInstance(teardown_success, bool)
    
    def test_dictionary_only_mutator_methods(self):
        """Test that DictionaryOnlyMutator has required methods."""
        mutator = DictionaryOnlyMutator()
        
        # Should have teardown method (default implementation)
        mutator.teardown()  # Should not raise exception
    
    def test_scapy_mutator_methods(self):
        """Test that ScapyMutator has required methods."""
        mutator = ScapyMutator()
        
        # Should have teardown method (default implementation)
        mutator.teardown()  # Should not raise exception
    
    def test_mutator_manager_teardown(self):
        """Test MutatorManager teardown functionality."""
        from scapy.layers.inet import IP, TCP
        packet = IP(dst="127.0.0.1") / TCP(dport=80)
        config = FuzzConfig(packets=[packet])
        manager = MutatorManager(config)
        
        # Should not raise exception
        manager.teardown()
        
        # Multiple teardown calls should be safe
        manager.teardown()
    
    def test_mutator_manager_automatic_teardown(self):
        """Test MutatorManager automatic teardown via __del__."""
        from scapy.layers.inet import IP, TCP
        packet = IP(dst="127.0.0.1") / TCP(dport=80)
        config = FuzzConfig(packets=[packet])
        manager = MutatorManager(config)
        
        # Delete should trigger teardown automatically
        del manager
        # If we get here without exception, teardown worked
    
    def test_corpus_initialization_with_empty_seed_data(self):
        """Test corpus initialization with empty seed data."""
        mutator = LibFuzzerMutator()
        
        try:
            # Empty seed data should not cause errors
            success = mutator.initialize(self.string_field, [])
            self.assertIsInstance(success, bool)
            
            # None values in seed data should be handled gracefully
            success = mutator.initialize(self.string_field, [None, None])
            self.assertIsInstance(success, bool)
        
        finally:
            mutator.teardown()
    
    def test_corpus_initialization_error_handling(self):
        """Test that corpus initialization handles errors gracefully."""
        mutator = LibFuzzerMutator()
        
        try:
            # Invalid field info should not crash
            invalid_field = namedtuple('InvalidField', [])()
            success = mutator.initialize(invalid_field, self.seed_data)
            self.assertIsInstance(success, bool)
            
            # Should handle exceptions gracefully
            success = mutator.initialize(None, self.seed_data)
            self.assertIsInstance(success, bool)
        
        finally:
            mutator.teardown()


if __name__ == '__main__':
    unittest.main()
