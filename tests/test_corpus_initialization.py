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
            candidates = mutator.initialize(self.string_field, self.seed_data)
            self.assertIsInstance(candidates, list)
            
            if mutator.is_libfuzzer_available():
                # LibFuzzer is available, should generate candidates
                self.assertGreater(len(candidates), 0, "Should generate corpus candidates when LibFuzzer is available")
                
                # All candidates should be strings for string field
                for candidate in candidates:
                    self.assertIsInstance(candidate, str, f"String field candidate should be string, got {type(candidate)}")
            else:
                # LibFuzzer not available, should return empty list
                self.assertEqual(len(candidates), 0, "Should return empty list when LibFuzzer not available")
            
            # Test numeric field corpus initialization
            numeric_candidates = mutator.initialize(self.numeric_field, self.seed_data)
            self.assertIsInstance(numeric_candidates, list)
            
            if mutator.is_libfuzzer_available() and len(numeric_candidates) > 0:
                # All candidates should be integers for numeric field
                for candidate in numeric_candidates:
                    self.assertIsInstance(candidate, int, f"Numeric field candidate should be int, got {type(candidate)}")
                    self.assertGreaterEqual(candidate, 0, "Numeric candidates should respect min_value")
                    self.assertLessEqual(candidate, 1000, "Numeric candidates should respect max_value")
            
            # Test raw field corpus initialization
            raw_candidates = mutator.initialize(self.raw_field, self.seed_data)
            self.assertIsInstance(raw_candidates, list)
            
            if mutator.is_libfuzzer_available() and len(raw_candidates) > 0:
                # All candidates should be bytes for raw field
                for candidate in raw_candidates:
                    self.assertIsInstance(candidate, bytes, f"Raw field candidate should be bytes, got {type(candidate)}")
        
        finally:
            # Test teardown
            mutator.teardown()
            
            # Check that corpus directory was cleaned up
            if hasattr(mutator, '_corpus_dir') and mutator._corpus_dir:
                self.assertFalse(Path(mutator._corpus_dir).exists(), "Corpus directory should be cleaned up after teardown")
    
    def test_dictionary_only_mutator_methods(self):
        """Test that DictionaryOnlyMutator has corpus methods."""
        mutator = DictionaryOnlyMutator()
        
        # Should have corpus initialization method (default implementation)
        candidates = mutator.initialize(self.string_field, self.seed_data)
        self.assertIsInstance(candidates, list)
        self.assertEqual(len(candidates), 0, "Default implementation should return empty list")
        
        # Should have teardown method (default implementation)
        mutator.teardown()  # Should not raise exception
    
    def test_scapy_mutator_methods(self):
        """Test that ScapyMutator has corpus methods."""
        mutator = ScapyMutator()
        
        # Should have corpus initialization method (default implementation)
        candidates = mutator.initialize(self.string_field, self.seed_data)
        self.assertIsInstance(candidates, list)
        self.assertEqual(len(candidates), 0, "Default implementation should return empty list")
        
        # Should have teardown method (default implementation)
        mutator.teardown()  # Should not raise exception
    
    def test_mutator_manager_teardown(self):
        """Test MutatorManager teardown functionality."""
        config = FuzzConfig()
        manager = MutatorManager(config)
        
        # Should not raise exception
        manager.teardown()
        
        # Multiple teardown calls should be safe
        manager.teardown()
    
    def test_mutator_manager_automatic_teardown(self):
        """Test MutatorManager automatic teardown via __del__."""
        config = FuzzConfig()
        manager = MutatorManager(config)
        
        # Delete should trigger teardown automatically
        del manager
        # If we get here without exception, teardown worked
    
    def test_corpus_initialization_with_empty_seed_data(self):
        """Test corpus initialization with empty seed data."""
        mutator = LibFuzzerMutator()
        
        try:
            # Empty seed data should not cause errors
            candidates = mutator.initialize(self.string_field, [])
            self.assertIsInstance(candidates, list)
            self.assertEqual(len(candidates), 0, "Empty seed data should return empty candidates")
            
            # None values in seed data should be handled gracefully
            candidates = mutator.initialize(self.string_field, [None, None])
            self.assertIsInstance(candidates, list)
        
        finally:
            mutator.teardown()
    
    def test_corpus_initialization_error_handling(self):
        """Test that corpus initialization handles errors gracefully."""
        mutator = LibFuzzerMutator()
        
        try:
            # Invalid field info should not crash
            invalid_field = namedtuple('InvalidField', [])()
            candidates = mutator.initialize(invalid_field, self.seed_data)
            self.assertIsInstance(candidates, list)
            
            # Should handle exceptions gracefully
            candidates = mutator.initialize(None, self.seed_data)
            self.assertIsInstance(candidates, list)
        
        finally:
            mutator.teardown()


if __name__ == '__main__':
    unittest.main()
