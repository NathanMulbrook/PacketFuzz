#!/usr/bin/env python3
"""
Layer utilities for PacketFuzz framework.

Provides functions to get layer names from both Scapy's built-in layer registry
and PacketFuzz's fuzzing categories, combining real packet layers with logical
fuzzing groupings.
"""

from typing import Set, Optional, Dict, Union
import logging

logger = logging.getLogger(__name__)

# Cache for layer names to avoid repeated Scapy registry lookups
_layer_cache: Dict[str, Optional[Set[str]]] = {
    'all_layers': None,
    'scapy_layers': None, 
    'fuzzing_categories': None
}


def get_all_known_layer_names() -> Set[str]:
    """
    Get comprehensive set of layer names from both Scapy layers and fuzzing categories.
    
    Combines:
    1. Real Scapy packet layers (TCP, UDP, IP, etc.)
    2. PacketFuzz logical fuzzing categories (Auth, Debug, File, etc.)
    
    Returns:
        Set of all known layer names that can be used in layers_to_fuzz/excluded_layers
    """
    # Return cached result if available
    if _layer_cache['all_layers'] is not None:
        return _layer_cache['all_layers']
    
    all_layer_names = set()
    
    # Method 1: Get real Scapy layer names using built-in registry
    try:
        from scapy.config import conf
        
        # Extract layer class names from Scapy's registry
        for layer_class in conf.layers:
            if hasattr(layer_class, '__name__'):
                name = layer_class.__name__
                # Filter out internal/system layers that aren't useful for fuzzing
                if (not name.startswith('_') and 
                    not 'rtattr' in name.lower() and
                    name not in ['Packet', 'NoPayload']):
                    all_layer_names.add(name)
                    
        logger.debug(f"Found {len(all_layer_names)} layer names from Scapy registry")
        
    except ImportError as e:
        logger.warning(f"Could not import Scapy config: {e}")
        raise
    except Exception as e:
        logger.warning(f"Error accessing Scapy layer registry: {e}")
        raise
    
    # Method 2: Get fuzzing categories from FIELD_NAME_WEIGHTS
    try:
        from ..default_mappings import FIELD_NAME_WEIGHTS
        
        # Extract layer names from field keys (preserves fuzzing categories)
        fuzzing_categories = set()
        for field_key in FIELD_NAME_WEIGHTS.keys():
            if '.' in field_key:
                layer_name = field_key.split('.', 1)[0]
                fuzzing_categories.add(layer_name)
        
        all_layer_names.update(fuzzing_categories)
        logger.debug(f"Added {len(fuzzing_categories)} fuzzing categories from FIELD_NAME_WEIGHTS")
        
    except ImportError as e:
        logger.warning(f"Could not import default_mappings: {e}")
        raise
    except Exception as e:
        logger.warning(f"Error accessing FIELD_NAME_WEIGHTS: {e}")
        raise
    
    # Cache the result
    _layer_cache['all_layers'] = all_layer_names
    logger.debug(f"Total known layer names: {len(all_layer_names)}")
    return all_layer_names


def get_layer_names_from_packets(packets) -> Set[str]:
    """
    Extract layer names from packet(s) using Scapy's built-in methods.
    
    Handles single packets, lists, or Scapy PacketList objects.
    Most efficient approach - only considers layers actually present.
    
    Args:
        packets: Single packet, list of packets, or PacketList
        
    Returns:
        Set of layer names present in the packet(s)
    """
    if not packets:
        return set()
    
    # Normalize to iterable (handle single packet, lists, PacketList)
    from scapy.plist import PacketList
    if not isinstance(packets, (list, tuple, PacketList)):
        packets = [packets]
    
    # Extract all unique layer names using Scapy's layers() method
    return {cls.__name__ for packet in packets if packet for cls in packet.layers()}


def get_smart_layer_names(packets=None, include_fuzzing_categories=True) -> Set[str]:
    """
    Smart layer name extraction with packet-first approach.
    
    Strategy (in order of preference):
    1. Extract from actual packets (most accurate and efficient)
    2. Add fuzzing categories from FIELD_NAME_WEIGHTS
    3. Add common fallback layers if needed
    
    Args:
        packets: Single packet, list of packets, or None
        include_fuzzing_categories: Whether to include logical fuzzing categories
        
    Returns:
        Set of relevant layer names
    """
    all_layer_names = set()
    
    # Method 1: Extract from actual packets (preferred)
    if packets is not None:
        packet_layers = get_layer_names_from_packets(packets)
        all_layer_names.update(packet_layers)
        logger.debug(f"Found {len(packet_layers)} layers from packets: {packet_layers}")
    
    # Method 2: Add fuzzing categories (for logical groupings like "Auth", "Debug")
    if include_fuzzing_categories:
        try:
            from ..default_mappings import FIELD_NAME_WEIGHTS
            fuzzing_categories = {
                field_key.split('.', 1)[0] 
                for field_key in FIELD_NAME_WEIGHTS.keys() 
                if '.' in field_key
            }
            all_layer_names.update(fuzzing_categories)
            logger.debug(f"Added {len(fuzzing_categories)} fuzzing categories")
        except ImportError as e:
            logger.warning(f"Could not import default_mappings: {e}")
    
    # Method 3: Fallback to common layers (only if we have very few)
    if len(all_layer_names) < 10:
        common_layers = {
            'Ether', 'IP', 'IPv6', 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'DHCP',
            'Raw', 'Padding', 'HTTPRequest', 'HTTPResponse', 'HTTP'
        }
        all_layer_names.update(common_layers)
        logger.debug("Added common fallback layers")
    
    logger.debug(f"Total layer names: {len(all_layer_names)}")
    return all_layer_names
    """
    Get only real Scapy packet layer names (excludes fuzzing categories).
    
    Returns:
        Set of actual Scapy layer class names
    """
    scapy_layers = set()
    
    try:
        from scapy.config import conf
        
        for layer_class in conf.layers:
            if hasattr(layer_class, '__name__'):
                name = layer_class.__name__
                # Filter out internal/system layers
                if (not name.startswith('_') and 
                    not 'rtattr' in name.lower() and
                    name not in ['Packet', 'NoPayload']):
                    scapy_layers.add(name)
                    
    except Exception as e:
        logger.warning(f"Error getting Scapy layer names: {e}")
    
    return scapy_layers


def get_scapy_layer_names() -> Set[str]:
    """
    Get only real Scapy packet layer names (excludes fuzzing categories).
    
    Returns:
        Set of actual Scapy layer class names
    """
    scapy_layers = set()
    
    try:
        from scapy.config import conf
        
        for layer_class in conf.layers:
            if hasattr(layer_class, '__name__'):
                name = layer_class.__name__
                # Filter out internal/system layers
                if (not name.startswith('_') and 
                    not 'rtattr' in name.lower() and
                    name not in ['Packet', 'NoPayload']):
                    scapy_layers.add(name)
                    
    except Exception as e:
        logger.warning(f"Error getting Scapy layer names: {e}")
    
    return scapy_layers


def get_fuzzing_category_names() -> Set[str]:
    """
    Get fuzzing category names from FIELD_NAME_WEIGHTS (excludes real Scapy layers).
    
    These are logical groupings like "Auth", "Debug", "File" that represent
    fuzzing categories rather than actual packet layers.
    
    Returns:
        Set of fuzzing category names
    """
    try:
        from ..default_mappings import FIELD_NAME_WEIGHTS
        
        # Get all layer names from field keys
        all_from_weights = set()
        for field_key in FIELD_NAME_WEIGHTS.keys():
            if '.' in field_key:
                layer_name = field_key.split('.', 1)[0]
                all_from_weights.add(layer_name)
        
        # Subtract real Scapy layer names to get only fuzzing categories
        scapy_layers = get_scapy_layer_names()
        fuzzing_categories = all_from_weights - scapy_layers
        
        return fuzzing_categories
        
    except Exception as e:
        logger.warning(f"Error getting fuzzing category names: {e}")
        return set()


def is_valid_layer_name(layer_name: str) -> bool:
    """
    Check if a layer name is valid (either real Scapy layer or fuzzing category).
    
    Args:
        layer_name: Layer name to validate
        
    Returns:
        True if the layer name is recognized
    """
    all_known = get_all_known_layer_names()
    return layer_name in all_known
