#!/usr/bin/env python3
"""
Field Analysis Utilities for PacketFuzz

Consolidated field type resolution with embedded config support and Scapy inheritance.
Provides single source of truth for field type analysis across the fuzzing framework.
"""

import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


def find_field_descriptor(packet, field_name: str):
    """
    Look up field descriptor by name in packet's field definitions.
    
    Args:
        packet: The packet object
        field_name: Name of the field to find
        
    Returns:
        Field descriptor object if found, None otherwise
    """
    for field_desc in packet.__class__.fields_desc:
        if field_desc.name == field_name:
            return field_desc
    return None


def get_field_type_chain(packet, field_name: str) -> List[str]:
    """
    CONSOLIDATED field type resolution with embedded config support.
    
    Returns type inheritance chain: [primary_type, parent1, parent2, ...]
    Handles embedded configs that can override Scapy types.
    
    Args:
        packet: The packet object (for embedded config lookup and field_desc lookup)
        field_name: The field name (for embedded config lookup and field_desc lookup)
    
    Returns:
        List of type names from most specific to most general.
        Example: ['_HTTPHeaderField', 'StrField', '_StrField', 'Field']
        With override: ['custom_type']  # embedded config is authoritative
    """
    # Look up field_desc from packet and field_name
    field_desc = find_field_descriptor(packet, field_name)
    if field_desc is None:
        logger.warning(f"Field '{field_name}' not found in {type(packet).__name__}")
        return []
    
    type_chain = []
    
    # Check for embedded type override first
    if packet and field_name and hasattr(packet, 'get_field_fuzz_config'):
        field_config = packet.get_field_fuzz_config(field_name)
        if field_config and hasattr(field_config, 'type') and field_config.type:
            # Embedded config overrides Scapy type completely
            logger.debug(f"Field {field_name} using embedded type override: {field_config.type}")
            type_chain.append(field_config.type)
            return type_chain  # Early return - embedded config is authoritative
    
    # Standard Scapy field analysis with inheritance
    if field_desc:
        # Primary type
        field_type_name = type(field_desc).__name__
        type_chain.append(field_type_name)
        
        # Parent classes in MRO order (excluding object and Field base)
        for cls in type(field_desc).__mro__[1:]:
            parent_name = cls.__name__
            if parent_name not in ('Field', 'object'):
                type_chain.append(parent_name)
        
        # Only log type chain discovery once per field type to reduce log spam
        if not hasattr(get_field_type_chain, '_logged_types'):
            get_field_type_chain._logged_types = set()
        
        field_id = f"{field_type_name}:{getattr(field_desc, 'name', 'unknown')}"
        if field_id not in get_field_type_chain._logged_types:
            logger.debug(f"Field type chain for {getattr(field_desc, 'name', 'unknown')}: {type_chain}")
            get_field_type_chain._logged_types.add(field_id)
    
    return type_chain


def resolve_field_weight(packet, field_name: str) -> Optional[float]:
    """
    CONSOLIDATED weight resolution with type inheritance.
    
    Returns first matching weight from type chain, or None if no match.
    
    Args:
        packet: The packet object (for embedded config lookup and field_desc lookup)  
        field_name: The field name (for embedded config lookup and field_desc lookup)
    
    Returns:
        Weight value (0.0-1.0) or None if no match found
    """
    # Import here to avoid circular imports
    from ..default_mappings import FIELD_TYPE_WEIGHTS
    
    type_chain = get_field_type_chain(packet, field_name)
    
    for field_type in type_chain:
        if field_type in FIELD_TYPE_WEIGHTS:
            logger.debug(f"Found weight {FIELD_TYPE_WEIGHTS[field_type]} for type {field_type}")
            return FIELD_TYPE_WEIGHTS[field_type]
    
    logger.debug(f"No weight found for type chain: {type_chain}")
    return None


def resolve_field_dictionaries(packet, field_name: str) -> List[str]:
    """
    CONSOLIDATED dictionary resolution with type inheritance.
    
    Returns list of dictionaries from first matching type in chain.
    
    Args:
        packet: The packet object (for embedded config lookup and field_desc lookup)
        field_name: The field name (for embedded config lookup and field_desc lookup)  
    
    Returns:
        List of dictionary paths (may be empty if no match)
    """
    # Import here to avoid circular imports
    from ..default_mappings import FIELD_TYPE_DICTIONARIES
    
    type_chain = get_field_type_chain(packet, field_name)
    
    for field_type in type_chain:
        if field_type in FIELD_TYPE_DICTIONARIES:
            dictionaries = FIELD_TYPE_DICTIONARIES[field_type].copy()
            logger.debug(f"Found dictionaries for type {field_type}: {dictionaries}")
            return dictionaries
    
    logger.debug(f"No dictionaries found for type chain: {type_chain}")
    return []


def extract_field_properties(packet, field_name: str) -> dict:
    """
    Extract field properties from Scapy field descriptor.
    
    Properties include length constraints, context information, and other
    metadata used by advanced mapping resolution.
    
    Args:
        packet: The packet object (for context and field_desc lookup)
        field_name: The field name (for context and field_desc lookup)
    
    Returns:
        dict with extracted properties:
        - length: Field size/length constraint (int or callable)
        - context: Additional context information
        - size: Field byte size
        - length_from: Length computation function
        - length_of: Field this describes the length of
        - is_length_field: Whether this field controls the length of another
    """
    # Look up field_desc from packet and field_name
    field_desc = find_field_descriptor(packet, field_name)
    
    properties = {}
    
    if not field_desc:
        return properties
    
    # Extract size/length information
    if hasattr(field_desc, 'sz') and field_desc.sz is not None:
        properties['size'] = field_desc.sz
        if isinstance(field_desc.sz, (int, float)) and field_desc.sz > 0:
            properties['length'] = int(field_desc.sz)
    
    # Length computation functions
    if hasattr(field_desc, 'length_from') and field_desc.length_from is not None:
        properties['length_from'] = field_desc.length_from
        # Try to compute actual length if possible
        if packet and callable(field_desc.length_from):
            try:
                computed_length = field_desc.length_from(packet)
                if isinstance(computed_length, int):
                    properties['length'] = computed_length
            except Exception:
                pass  # Couldn't compute length, that's OK
    
    # Length control (this field controls another field's length)
    if hasattr(field_desc, 'length_of') and field_desc.length_of is not None:
        properties['length_of'] = field_desc.length_of
        properties['is_length_field'] = True
    
    # Check for count-based fields
    if hasattr(field_desc, 'count_from') and field_desc.count_from is not None:
        properties['count_from'] = field_desc.count_from
    
    # Context information
    if packet and field_name:
        # Add packet type as context
        properties['context'] = type(packet).__name__
        
        # Check if this is a length-related field by name
        if 'len' in field_name.lower() or 'length' in field_name.lower():
            properties['is_length_field'] = True
            
        # Add layer position context
        packet_layers = []
        current = packet
        while current and current.__class__.__name__ != 'NoPayload':
            packet_layers.append(current.__class__.__name__)
            current = current.payload if hasattr(current, 'payload') else None
        
        if packet_layers:
            layer_index = next((i for i, layer in enumerate(packet_layers) 
                              if layer == type(packet).__name__), -1)
            if layer_index >= 0:
                properties['layer_position'] = layer_index
                properties['total_layers'] = len(packet_layers)
    
    # Field format information
    if hasattr(field_desc, 'fmt') and field_desc.fmt is not None:
        properties['format'] = field_desc.fmt
    
    return properties
