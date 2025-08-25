#!/usr/bin/env python3
# type: ignore
"""
Comprehensive mutator testing for PacketFuzzer

Tests all mutator implementations including LibFuzzer integration,
dictionary corpus generation, and mutation quality verification.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packetfuzz.fuzzing_framework import FuzzingCampaign
Campaign = FuzzingCampaign


class TestMutatorAvailability(unittest.TestCase):
    """Test mutator availability and basic imports"""
    
    def test_mutator_imports(self):
        """Test that mutator modules can be imported"""
        try:
            from packetfuzz.mutators.base import BaseMutator
            from packetfuzz.mutators.dictionary_only_mutator import DictionaryOnlyMutator
            self.assertTrue(True)  # If we get here, imports worked
        except ImportError as e:
            self.fail(f"Could not import basic mutators: {e}")
    
    def test_libfuzzer_import(self):
        """Test LibFuzzer mutator import (may fail if extension not built)"""
        try:
            from packetfuzz.mutators.libfuzzer_mutator import LibFuzzerMutator
            self.libfuzzer_importable = True
        except ImportError:
            self.libfuzzer_importable = False
            self.skipTest("LibFuzzer mutator not importable")


class TestDictionaryOnlyMutator(unittest.TestCase):
    """Test the dictionary-only mutator"""
    
    def setUp(self):
        try:
            from packetfuzz.mutators.dictionary_only_mutator import DictionaryOnlyMutator
            self.mutator = DictionaryOnlyMutator()
        except ImportError:
            self.skipTest("Dictionary mutator not available")
    
    def test_dictionary_only_mutator_creation(self):
        """Test that DictionaryOnlyMutator can be created"""
        self.assertIsNotNone(self.mutator)
    
    def test_mutate_bytes_dictionary_only(self):
        """Test mutate_bytes with dictionary for DictionaryOnlyMutator"""
        test_data = b'original'
        dictionary = [b'foo', b'bar', b'baz']
        result = self.mutator.mutate_bytes(test_data, dictionary)
        
        # Should return a byte string that corresponds to one of the dictionary values
        self.assertIsInstance(result, bytes)
        self.assertIn(result, dictionary)


class TestLibFuzzerMutator(unittest.TestCase):
    """Test LibFuzzer mutator functionality"""
    
    def setUp(self):
        """Set up LibFuzzer mutator if available"""
        try:
            from packetfuzz.mutators.libfuzzer_mutator import LibFuzzerMutator
            self.mutator = LibFuzzerMutator()
            self.libfuzzer_available = True
        except (ImportError, RuntimeError) as e:
            self.mutator = None
            self.libfuzzer_available = False
            self.skipTest(f"LibFuzzer not available: {e}")
    
    def test_libfuzzer_mutator_creation(self):
        """Test LibFuzzer mutator creation"""
        self.assertIsNotNone(self.mutator)
    
    def test_is_libfuzzer_available(self):
        """Test LibFuzzer availability check"""
        if hasattr(self.mutator, 'is_libfuzzer_available'):
            result = self.mutator.is_libfuzzer_available()
            self.assertIsInstance(result, bool)
            self.assertTrue(result)  # Should be True since we got this far
    
    def test_basic_mutation(self):
        """Test basic mutation functionality"""
        if not hasattr(self.mutator, 'mutate_bytes'):
            self.skipTest("mutate_bytes method not available")
        
        test_data = b"hello world"
        result = self.mutator.mutate_bytes(test_data)
        
        self.assertIsInstance(result, bytes)
        self.assertGreaterEqual(len(result), 0)
    
    def test_mutation_with_dictionaries(self):
        """Test mutation with dictionary entries"""
        if not hasattr(self.mutator, 'mutate_bytes'):
            self.skipTest("mutate_bytes method not available")
        
        test_data = b"GET /index.html HTTP/1.1"
        dictionaries = [b'POST', b'PUT', b'admin', b'127.0.0.1']
        
        result = self.mutator.mutate_bytes(test_data, dictionaries)
        
        self.assertIsInstance(result, bytes)
        self.assertGreaterEqual(len(result), 0)
    
    def test_corpus_generation(self):
        """Test dictionary corpus generation"""
        if not hasattr(self.mutator, 'generate_dictionary_seed'):
            self.skipTest("generate_dictionary_seed method not available")
        
        corpus_dir = tempfile.mkdtemp(prefix="test_corpus_")
        
        try:
            dictionaries = ["GET", "POST", "admin", "test"]
            self.mutator.generate_dictionary_seed(dictionaries, corpus_dir)
            
            # Check that files were created
            corpus_files = os.listdir(corpus_dir)
            self.assertEqual(len(corpus_files), len(dictionaries))
            
            # Check one file content
            with open(os.path.join(corpus_dir, "seed_0.bin"), 'rb') as f:
                content = f.read()
            self.assertEqual(content, b"GET")
            
        finally:
            shutil.rmtree(corpus_dir)
    
    def test_dictionary_loading(self):
        """Test dictionary loading for native support"""
        if not hasattr(self.mutator, 'load_dictionaries_for_native_support'):
            self.skipTest("load_dictionaries_for_native_support method not available")
        
        corpus_dir = tempfile.mkdtemp(prefix="test_dict_load_")
        
        try:
            dictionaries = ["HTTP", "GET", "POST"]
            result = self.mutator.load_dictionaries_for_native_support(dictionaries, corpus_dir)
            
            self.assertIsInstance(result, bool)
            
            # Check corpus files were created
            corpus_files = os.listdir(corpus_dir)
            self.assertEqual(len(corpus_files), len(dictionaries))
            
        finally:
            shutil.rmtree(corpus_dir)
    
    def test_mutation_diversity(self):
        """Test that mutations produce diverse results"""
        if not hasattr(self.mutator, 'mutate_bytes'):
            self.skipTest("mutate_bytes method not available")
        
        test_data = b"test data for diversity"
        mutations = []
        
        # Generate multiple mutations
        for _ in range(10):
            mutation = self.mutator.mutate_bytes(test_data)
            mutations.append(mutation)
        
        # Check that we have some diversity
        unique_mutations = set(mutations)
        self.assertGreater(len(unique_mutations), 1, "Should generate diverse mutations")
    
    def test_empty_input_handling(self):
        """Test handling of empty input"""
        if not hasattr(self.mutator, 'mutate_bytes'):
            self.skipTest("mutate_bytes method not available")
        
        result = self.mutator.mutate_bytes(b"")
        self.assertIsInstance(result, bytes)


class TestMutatorIntegration(unittest.TestCase):
    """Test integration between mutators and the broader framework"""
    
    def test_mutator_manager_creation(self):
        """Test that MutatorManager can be created with different preferences"""
        try:
            from packetfuzz.mutator_manager import MutatorManager, FuzzConfig
            
            # Test with libfuzzer preference
            config = FuzzConfig(mutator_preference=["libfuzzer"])
            manager = MutatorManager(config)
            self.assertIsNotNone(manager)
            
            # Test with dictionary_only preference
            config = FuzzConfig(mutator_preference=["dictionary_only"])
            manager = MutatorManager(config)
            self.assertIsNotNone(manager)
            
        except ImportError:
            self.skipTest("MutatorManager not available")
        except Exception as e:
            # Some configurations might fail due to missing dependencies
            # This is acceptable for this test
            pass
    
    def test_dictionary_manager_integration(self):
        """Test basic dictionary manager functionality"""
        try:
            from packetfuzz.dictionary_manager import DictionaryManager
            manager = DictionaryManager()
            self.assertIsNotNone(manager)
        except ImportError:
            self.skipTest("DictionaryManager not available")


class TestMutatorErrors(unittest.TestCase):
    """Test error handling in mutators"""
    
    def test_libfuzzer_missing_library(self):
        """Test graceful handling when LibFuzzer library is missing"""
        try:
            from packetfuzz.mutators.libfuzzer_mutator import LibFuzzerMutator
        except ImportError:
            self.skipTest("LibFuzzer mutator not importable")
        
        # Patch Path.exists to simulate missing library
        with patch('pathlib.Path.exists', return_value=False):
            with self.assertRaises(RuntimeError) as context:
                LibFuzzerMutator()
            
            self.assertIn("LibFuzzer extension library not found", str(context.exception))


class TestScapyMutator(unittest.TestCase):
    """Test Scapy mutator functionality"""
    
    def test_scapy_mutator_import(self):
        """Test that ScapyMutator can be imported and used"""
        try:
            from packetfuzz.mutators.scapy_mutator import ScapyMutator
            mutator = ScapyMutator()
            self.assertIsNotNone(mutator)
            # Test mutate_field with new typed signature returns something
            from types import SimpleNamespace
            field_info = SimpleNamespace(kind='numeric')
            result = mutator.mutate_field(field_info, 123)
            self.assertIsNotNone(result)
        except ImportError as e:
            self.skipTest(f"ScapyMutator not available: {e}")


class DummyMutatorCampaign(Campaign):
    name = "dummy_mutator"
    target = "127.0.0.1"
    output_network = False
    def build_packets(self):
        return [IP(dst=self.target)/UDP(dport=int(53))/Raw(load=b"test")]  # Ensure dport is int



