#!/usr/bin/env python3
"""
Test script for boofuzz wrapper functionality

Tests the boofuzz mutator integration to ensure it works correctly
with different field types and produces meaningful mutations.
"""

import sys
import logging
from pathlib import Path

# Add the PacketFuzz root directory to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from packetfuzz.mutators.boofuzz_mutator import BoofuzzMutator
from packetfuzz.mutators.boofuzz_adapters import (
    BoofuzzBytesAdapter, BoofuzzStringAdapter, BoofuzzDWordAdapter
)
from packetfuzz.mutator_manager_data import FieldMetadata

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

def test_boofuzz_string_adapter():
    """Test the string adapter directly"""
    print("\n=== Testing BoofuzzStringAdapter ===")
    
    adapter = BoofuzzStringAdapter()
    
    # Create test field metadata
    field_info = FieldMetadata(
        field_key="test_layer[0].test_string",
        layer_name="test_layer",
        field_name="test_string",
        layer_index=0,
        packet_index=0,
        field_type="StrField", 
        field_kind="string",
        current_value="hello"
    )
    
    print(f"Original value: {field_info.current_value}")
    
    # Test mutations
    for i in range(5):
        mutated = adapter.mutate_field(field_info)
        print(f"Mutation {i+1}: {repr(mutated)}")

def test_boofuzz_bytes_adapter():
    """Test the bytes adapter directly"""
    print("\n=== Testing BoofuzzBytesAdapter ===")
    
    adapter = BoofuzzBytesAdapter()
    
    # Test mutate_bytes
    original_data = b"test_data"
    print(f"Original bytes: {repr(original_data)}")
    
    for i in range(5):
        mutated = adapter.mutate_bytes(original_data)
        print(f"Mutation {i+1}: {repr(mutated)}")

def test_boofuzz_integer_adapter():
    """Test integer adapter"""
    print("\n=== Testing BoofuzzDWordAdapter ===")
    
    adapter = BoofuzzDWordAdapter()
    
    field_info = FieldMetadata(
        field_key="test_layer[0].test_int",
        layer_name="test_layer",
        field_name="test_int",
        layer_index=0,
        packet_index=0,
        field_type="IntField",
        field_kind="numeric",
        current_value=1234
    )
    
    print(f"Original value: {field_info.current_value}")
    
    for i in range(5):
        mutated = adapter.mutate_field(field_info)
        print(f"Mutation {i+1}: {mutated}")

def test_unified_boofuzz_mutator():
    """Test the unified boofuzz mutator"""
    print("\n=== Testing Unified BoofuzzMutator ===")
    
    mutator = BoofuzzMutator()
    
    # Test different field types
    test_fields = [
        FieldMetadata(
            field_key="test[0].str_field",
            layer_name="test", 
            field_name="str_field",
            layer_index=0,
            packet_index=0,
            field_type="StrField",
            field_kind="string", 
            current_value="test_string"
        ),
        FieldMetadata(
            field_key="test[0].int_field",
            layer_name="test",
            field_name="int_field", 
            layer_index=0,
            packet_index=0,
            field_type="IntField",
            field_kind="numeric",
            current_value=42
        ),
        FieldMetadata(
            field_key="test[0].byte_field",
            layer_name="test",
            field_name="byte_field",
            layer_index=0, 
            packet_index=0,
            field_type="ByteField",
            field_kind="numeric",
            current_value=255
        ),
        FieldMetadata(
            field_key="test[0].unknown_field",
            layer_name="test",
            field_name="unknown_field",
            layer_index=0,
            packet_index=0,
            field_type="CustomField",
            field_kind="binary",
            current_value=b"bytes_data"
        ),
    ]
    
    for field_info in test_fields:
        print(f"\nTesting field: {field_info.field_name} (type: {field_info.field_type})")
        print(f"Original: {repr(field_info.current_value)}")
        
        for i in range(3):
            mutated = mutator.mutate_field(field_info)
            print(f"  Mutation {i+1}: {repr(mutated)}")

def test_field_type_detection():
    """Test the field type mapping and fallback logic"""
    print("\n=== Testing Field Type Detection ===")
    
    mutator = BoofuzzMutator()
    
    # Show supported field types
    supported_types = mutator.get_supported_field_types()
    print(f"Supported field types: {len(supported_types)}")
    for field_type in sorted(supported_types):
        print(f"  - {field_type}")

def main():
    """Run all tests"""
    print("Testing Boofuzz Wrapper Implementation")
    print("=" * 50)
    
    try:
        test_boofuzz_string_adapter()
        test_boofuzz_bytes_adapter() 
        test_boofuzz_integer_adapter()
        test_unified_boofuzz_mutator()
        test_field_type_detection()
        
        print("\n" + "=" * 50)
        print("✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())