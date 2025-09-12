"""
Unified Boofuzz Mutator

Provides a single "boofuzz" mutator that automatically selects the appropriate 
boofuzz primitive based on field metadata. This is the main entry point for 
users who want to use boofuzz mutations.
"""

import logging
import random
from typing import Any, Dict, List, Optional, Type

from scapy.fields import (
    Field, ByteField, XByteField, ShortField, LEShortField, IntField, 
    LEIntField, LongField, LELongField, StrField, StrFixedLenField, 
    StrLenField, BitField, FlagsField, EnumField, IPField
)
from scapy.packet import Packet

from .base import BaseMutator
from ..mutator_manager_data import FieldMetadata
from .boofuzz_adapters import (
    BoofuzzBytesAdapter, BoofuzzStringAdapter, BoofuzzByteAdapter,
    BoofuzzWordAdapter, BoofuzzDWordAdapter, BoofuzzQWordAdapter, 
    BoofuzzFloatAdapter, BoofuzzRandomDataAdapter
)

logger = logging.getLogger(__name__)


class BoofuzzMutator(BaseMutator):
    """
    Unified boofuzz mutator that automatically selects appropriate boofuzz primitives
    based on field metadata. This provides a simple interface where users can just
    specify "boofuzz" as the mutator and get intelligent mutation selection.
    """
    
    # Mapping from Scapy field types to boofuzz adapter classes
    FIELD_TYPE_MAPPING: Dict[str, Type[BaseMutator]] = {
        # Byte-sized fields
        'ByteField': BoofuzzByteAdapter,
        'XByteField': BoofuzzByteAdapter,
        
        # 16-bit fields  
        'ShortField': BoofuzzWordAdapter,
        'LEShortField': BoofuzzWordAdapter,
        'BEShortField': BoofuzzWordAdapter,
        
        # 32-bit fields
        'IntField': BoofuzzDWordAdapter,
        'LEIntField': BoofuzzDWordAdapter,
        'BEIntField': BoofuzzDWordAdapter,
        'SignedIntField': BoofuzzDWordAdapter,
        'LESignedIntField': BoofuzzDWordAdapter,
        'BESignedIntField': BoofuzzDWordAdapter,
        
        # 64-bit fields
        'LongField': BoofuzzQWordAdapter,
        'LELongField': BoofuzzQWordAdapter,
        'BELongField': BoofuzzQWordAdapter,
        'SignedLongField': BoofuzzQWordAdapter,
        'LESignedLongField': BoofuzzQWordAdapter,
        'BESignedLongField': BoofuzzQWordAdapter,
        
        # String fields
        'StrField': BoofuzzStringAdapter,
        'StrFixedLenField': BoofuzzStringAdapter,
        'StrLenField': BoofuzzStringAdapter,
        'StrNullField': BoofuzzStringAdapter,
        'PaddedField': BoofuzzStringAdapter,
        
        # Bit fields
        'BitField': BoofuzzDWordAdapter,  # Most bit fields are 32-bit based
        'FlagsField': BoofuzzDWordAdapter,
        'BitEnumField': BoofuzzDWordAdapter,
        
        # Special fields
        'EnumField': BoofuzzDWordAdapter,  # Usually int-based
        'IPField': BoofuzzDWordAdapter,    # 32-bit IP addresses
        'IP6Field': BoofuzzBytesAdapter,   # 128-bit IPv6 addresses as bytes
        'MACField': BoofuzzBytesAdapter,   # 6-byte MAC addresses
        'FloatField': BoofuzzFloatAdapter,
        'DoubleField': BoofuzzFloatAdapter,
        
        # Raw data fields
        'FieldLenField': BoofuzzDWordAdapter,  # Usually length values
        'FieldListField': BoofuzzBytesAdapter,
        'PacketListField': BoofuzzBytesAdapter,
        'ConditionalField': BoofuzzBytesAdapter,  # Fallback to bytes
    }
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._adapter_cache: Dict[str, BaseMutator] = {}
        if seed is not None:
            random.seed(seed)
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz"
    
    def _get_adapter_for_field(self, field_info: FieldMetadata) -> BaseMutator:
        """
        Get the appropriate boofuzz adapter for a field based on its metadata.
        Uses caching to avoid recreating adapters.
        """
        # Create cache key based on field type and name
        cache_key = f"{field_info.field_type}_{field_info.field_name}"
        
        if cache_key in self._adapter_cache:
            return self._adapter_cache[cache_key]
        
        # Determine field type
        field_type_name = field_info.field_type
        
        # Look up adapter class
        adapter_class = self.FIELD_TYPE_MAPPING.get(field_type_name)
        
        if adapter_class is None:
            # Fallback logic based on field characteristics
            logger.debug(f"No specific mapping for field type '{field_type_name}', using fallback logic")
            
            current_value = field_info.current_value
            
            if isinstance(current_value, str):
                adapter_class = BoofuzzStringAdapter
            elif isinstance(current_value, int):
                # Choose integer adapter based on value size
                if -128 <= current_value <= 255:
                    adapter_class = BoofuzzByteAdapter
                elif -32768 <= current_value <= 65535:
                    adapter_class = BoofuzzWordAdapter
                elif -2147483648 <= current_value <= 4294967295:
                    adapter_class = BoofuzzDWordAdapter
                else:
                    adapter_class = BoofuzzQWordAdapter
            elif isinstance(current_value, float):
                adapter_class = BoofuzzFloatAdapter
            elif isinstance(current_value, bytes):
                adapter_class = BoofuzzBytesAdapter
            else:
                # Ultimate fallback - treat as bytes
                logger.debug(f"Using bytes adapter as ultimate fallback for field '{field_info.field_name}'")
                adapter_class = BoofuzzBytesAdapter
        
        # Create and cache adapter instance
        adapter = adapter_class(seed=None)  # Don't pass seed to avoid re-seeding
        self._adapter_cache[cache_key] = adapter
        
        logger.debug(f"Selected {adapter_class.__name__} for field '{field_info.field_name}' (type: {field_type_name})")
        return adapter
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """
        Mutate raw byte data. Since we don't have field metadata, we'll use
        the bytes adapter by default.
        """
        adapter = BoofuzzBytesAdapter()
        return adapter.mutate_bytes(data, dictionaries)
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """
        Mutate a field by automatically selecting the appropriate boofuzz primitive
        based on the field's metadata.
        """
        try:
            # Get the appropriate adapter for this field
            adapter = self._get_adapter_for_field(field_info)
            
            # Delegate to the adapter
            result = adapter.mutate_field(field_info, dictionaries, rng, layer)
            
            logger.debug(f"Mutated field '{field_info.field_name}' from {field_info.current_value} to {result}")
            return result
            
        except Exception as e:
            logger.warning(f"Error mutating field '{field_info.field_name}' with boofuzz: {e}")
            return field_info.current_value
    
    def initialize(self, field_metadata: FieldMetadata, seed_data: List[Any], rng: Optional[random.Random] = None) -> bool:
        """
        Initialize the mutator with seed data. We'll initialize the appropriate
        adapter based on the field metadata.
        """
        try:
            adapter = self._get_adapter_for_field(field_metadata)
            return adapter.initialize(field_metadata, seed_data, rng)
        except Exception as e:
            logger.warning(f"Error initializing boofuzz mutator for field '{field_metadata.field_name}': {e}")
            return False
    
    def teardown(self) -> None:
        """Clean up all cached adapters"""
        for adapter in self._adapter_cache.values():
            adapter.teardown()
        self._adapter_cache.clear()
    
    def get_supported_field_types(self) -> List[str]:
        """
        Get a list of explicitly supported field types.
        Note: The mutator also provides fallback support for unknown types.
        """
        return list(self.FIELD_TYPE_MAPPING.keys())
    
    def add_field_type_mapping(self, field_type: str, adapter_class: Type[BaseMutator]) -> None:
        """
        Add or override a field type mapping. Useful for extending support
        to custom field types.
        """
        self.FIELD_TYPE_MAPPING[field_type] = adapter_class
        logger.info(f"Added mapping: {field_type} -> {adapter_class.__name__}")
        
        # Clear cache for this field type to ensure new mapping is used
        keys_to_remove = [key for key in self._adapter_cache.keys() if key.startswith(f"{field_type}_")]
        for key in keys_to_remove:
            del self._adapter_cache[key]
