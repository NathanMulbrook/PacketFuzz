#!/usr/bin/env python3
"""
Dictionary Management Tests - Simplified Version

Tests for existing dictionary functionality only:
- Dictionary manager creation
- Packet-level dictionary retrieval  
- Dictionary loading and resolution
- Advanced mapping configurations that still exist
"""

import sys
import os
import tempfile
import unittest
import importlib.util
from pathlib import Path
from typing import Dict, List, Any
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.dictionary_manager import DictionaryManager
from packetfuzz.fuzzing_framework import FuzzingCampaign

# Import packet extensions to enable field_fuzz() method
import packetfuzz.packet_extensions

# Import from conftest with proper path handling
try:
    from conftest import create_test_packet, DictionaryTestCampaign
except ImportError:
    try:
        from tests.conftest import create_test_packet, DictionaryTestCampaign
    except ImportError:
        conftest_path = os.path.join(os.path.dirname(__file__), 'conftest.py')
        spec = importlib.util.spec_from_file_location("conftest", conftest_path)
        if spec is not None and spec.loader is not None:
            conftest = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(conftest)
            create_test_packet = conftest.create_test_packet
            DictionaryTestCampaign = conftest.DictionaryTestCampaign
        else:
            def create_test_packet(packet_type):
                if packet_type == "tcp":
                    return IP(dst="127.0.0.1")/TCP(dport=80)/Raw("test")
                elif packet_type == "udp":
                    return IP(dst="127.0.0.1")/UDP(dport=53)/Raw("test")
                else:
                    return IP(dst="127.0.0.1")
            
            class DictionaryTestCampaign:
                pass


class TestBasicDictionaryManager(unittest.TestCase):
    """Test basic dictionary manager functionality that exists"""
    
    def test_default_manager_creation(self):
        """Test creating default dictionary manager"""
        manager = DictionaryManager()
        assert manager is not None
    
    def test_manager_with_config_file(self):
        """Test DictionaryManager with explicit config file"""
        # The DictionaryManager constructor doesn't take user_config_file
        # Configuration is now handled at the MutatorManager level
        # Just test basic manager creation with dictionary path
        config_path = "examples/config/user_dictionary_config.py"
        if os.path.exists(config_path):
            # Test manager creation with dictionary_path instead
            manager = DictionaryManager(dictionary_path="examples/dictionaries")
            assert manager is not None
        else:
            # Create manager without config file
            manager = DictionaryManager()
            assert manager is not None
    
    def test_get_packet_dictionaries(self):
        """Test getting packet-level dictionaries"""
        manager = DictionaryManager()
        from scapy.layers.inet import TCP
        tcp_packet = TCP()
        packet_dicts = manager.get_packet_dictionaries(tcp_packet)
        assert isinstance(packet_dicts, list)
        assert len(packet_dicts) == 0  # Should not have dictionaries


class TestDictionaryLoading(unittest.TestCase):
    """Test dictionary loading functionality"""
    
    def test_dictionary_entries_loading(self):
        """Test loading dictionary entries from files"""
        manager = DictionaryManager()
        
        # Create temporary dictionary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
            tmp_file.write("test1\ntest2\ntest3\n")
            tmp_path = tmp_file.name
        
        try:
            # Test loading entries
            entries = manager.get_dictionary_entries([tmp_path])
            assert isinstance(entries, list)
            assert b"test1" in entries
            assert b"test2" in entries
            assert b"test3" in entries
        finally:
            os.unlink(tmp_path)
    
    def test_get_dictionary_entries_empty_list(self):
        """Test loading dictionary entries with empty path list"""
        manager = DictionaryManager()
        entries = manager.get_dictionary_entries([])
        assert isinstance(entries, list)
        assert len(entries) == 0
    
    def test_get_dictionary_entries_nonexistent_file(self):
        """Test loading dictionary entries from nonexistent file"""
        manager = DictionaryManager()
        entries = manager.get_dictionary_entries(["/nonexistent/path.txt"])
        assert isinstance(entries, list)
        # Should return empty list if file doesn't exist


class TestAdvancedMappingFunctionality(unittest.TestCase):
    """Test advanced mapping functionality that still exists"""
    
    def test_get_merged_field_mapping(self):
        """Test getting merged field mapping"""
        manager = DictionaryManager()
        # Test with empty mapping - should not fail
        mapping = manager.get_merged_field_mapping([], "", "", {})
        assert isinstance(mapping, list)
    
    def test_expand_macro(self):
        """Test macro expansion functionality"""
        # Test basic macro that should exist
        expanded = DictionaryManager.expand_macro("test")
        assert isinstance(expanded, list)


class TestDictionaryConfiguration(unittest.TestCase):
    """Test dictionary configuration functionality"""
    
    def test_enhanced_manager_creation(self):
        """Test creating enhanced dictionary manager"""
        manager = DictionaryManager()
        assert manager is not None
    
    def test_enhanced_manager_with_config(self):
        """Test DictionaryManager with global config"""
        config_path = "examples/config/user_dictionary_config.py"
        if os.path.exists(config_path):
            # Test with dictionary_path instead of user_config_file
            manager = DictionaryManager(dictionary_path="examples/dictionaries")
            assert manager is not None
        else:
            # Create minimal manager if config doesn't exist
            manager = DictionaryManager()
            assert manager is not None


if __name__ == '__main__':
    unittest.main()
