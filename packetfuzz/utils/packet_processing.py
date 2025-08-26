#!/usr/bin/env python3
"""
Packet Processing Utilities for PacketFuzz Framework

Provides pure functions for packet processing operations including layer extraction,
filtering, and repackaging. These utilities are designed to be reusable across
different campaign types (PCAP, JSON reimport, etc.) following composition over
inheritance principles.

Features:
- Layer extraction at specified protocol levels
- Include/exclude layer filtering
- Payload repackaging with custom templates
- Enhanced bytes-to-Scapy conversion with protocol hints
- Pure functions for easy testing and reusability
"""

# Standard library imports
import logging
from dataclasses import dataclass
from typing import List, Optional, Union

# Third-party imports
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration Data Structures
# ============================================================================

@dataclass
class PacketProcessingConfig:
    """Configuration for packet processing operations"""
    extract_at_layer: Optional[str] = None      # e.g., "UDP", "TCP", "IP", "Ethernet"
    include_layers: Optional[List[str]] = None  # e.g., ["HTTP", "DNS"] - only these layers
    exclude_layers: Optional[List[str]] = None  # e.g., ["Raw"] - exclude these layers
    repackage_template: Optional[Packet] = None # e.g., IP(dst="192.168.1.1") / UDP(dport=53)


# ============================================================================
# Pure Packet Processing Functions
# ============================================================================

def extract_layers(packet: Optional[Packet], 
                  extract_at_layer: Optional[str] = None,
                  include_layers: Optional[List[str]] = None,
                  exclude_layers: Optional[List[str]] = None) -> Optional[Packet]:
    """
    Extract layers based on extraction rules.
    
    Args:
        packet: The packet to extract from
        extract_at_layer: Layer name to extract at (e.g., "UDP", "TCP")
        include_layers: Only keep these layer types
        exclude_layers: Remove these layer types
        
    Returns:
        The extracted layers or None if extraction failed
    """
    if packet is None:
        return None
        
    # Step 1: Find extraction point
    if extract_at_layer:
        layer = packet
        while layer and layer.name != extract_at_layer:
            layer = layer.payload
        if not layer or layer.name != extract_at_layer:
            return None
        extracted = layer.payload if layer.payload else None
    else:
        extracted = packet
    
    if not extracted:
        return None
    
    # Step 2: Apply include/exclude filters
    # Note: include_layers takes precedence over exclude_layers if both are specified
    if include_layers:
        result = filter_include_layers(extracted, include_layers)
    elif exclude_layers:
        result = filter_exclude_layers(extracted, exclude_layers)
    else:
        result = extracted
    
    return result


def filter_include_layers(packet: Optional[Packet], include: List[str]) -> Optional[Packet]:
    """
    Keep only specified layers.
    
    Args:
        packet: The packet to filter
        include: List of layer names to keep
        
    Returns:
        Filtered packet with only included layers
    """
    if packet is None or not include:
        return None
        
    current = packet
    result = None
    
    while current:
        if current.name in include:
            # Create a new packet of the same type with same fields but no payload
            new_layer = current.__class__()
            
            # Copy all fields except payload
            for field_name, field_value in current.fields.items():
                if field_name != 'payload':
                    setattr(new_layer, field_name, field_value)
            
            if result is None:
                result = new_layer
            else:
                tail = result
                while tail.payload:
                    tail = tail.payload
                tail.payload = new_layer
        current = current.payload
    
    return result


def filter_exclude_layers(packet: Optional[Packet], exclude: List[str]) -> Optional[Packet]:
    """
    Remove specified layers.
    
    Args:
        packet: The packet to filter
        exclude: List of layer names to remove
        
    Returns:
        Filtered packet with excluded layers removed
    """
    if packet is None or not exclude:
        return packet
        
    if packet.name in exclude:
        return filter_exclude_layers(packet.payload, exclude) if packet.payload else None
    
    # Create a new packet of the same type with same fields but no payload
    result = packet.__class__()
    
    # Copy all fields except payload
    for field_name, field_value in packet.fields.items():
        if field_name != 'payload':
            setattr(result, field_name, field_value)
    
    # Recursively filter the payload
    if packet.payload:
        filtered_payload = filter_exclude_layers(packet.payload, exclude)
        if filtered_payload:
            result.payload = filtered_payload
    
    return result


def repackage_payload(payload: Packet, template: Optional[Packet]) -> Packet:
    """
    Repackage extracted payload using user-provided template.
    
    Args:
        payload: The extracted payload to repackage
        template: The packet template to wrap the payload in (or None for no repackaging)
        
    Returns:
        The repackaged packet or original payload if no template
    """
    if template is None:
        return payload
        
    repackaged = template.copy()
    # Find the deepest layer in template and attach payload
    tail = repackaged
    while tail.payload:
        tail = tail.payload
    tail.payload = payload
    return repackaged


def convert_to_scapy(data: bytes, protocol_hint: Optional[str] = None) -> Packet:
    """
    Convert raw bytes back to Scapy packet with enhanced protocol detection.
    
    Args:
        data: Raw packet bytes
        protocol_hint: Optional hint about the protocol (e.g., "Ether", "IP")
        
    Returns:
        Scapy packet object
    """
    parsers = []
    
    # Use hint if provided
    if protocol_hint == 'Ether':
        parsers = [Ether, IP, Raw]
    elif protocol_hint == 'IP':
        parsers = [IP, Raw]
    else:
        # Auto-detect based on first few bytes
        if len(data) >= 14 and data[12:14] == b'\x08\x00':  # Ethernet with IP
            parsers = [Ether, IP, Raw]
        elif len(data) >= 1 and (data[0] >> 4) == 4:  # IPv4
            parsers = [IP, Raw]
        else:
            parsers = [Ether, IP, Raw]
    
    # Try parsers in order
    for parser in parsers:
        try:
            pkt = parser(data)
            # Prefer parsers that create multiple layers
            if hasattr(pkt, 'layers') and len(pkt.layers()) > 1:
                return pkt
        except Exception as e:
            logger.debug(f"Parser {parser.__name__} failed: {e}")
            continue
    
    # Fallback to Raw
    return Raw(data)


def process_packet(packet: Optional[Union[Packet, bytes]], config: Optional[PacketProcessingConfig]) -> Optional[Packet]:
    """
    Main packet processing pipeline that orchestrates all operations.
    
    Args:
        packet: The original packet to process
        config: Processing configuration
        
    Returns:
        The processed packet ready for fuzzing, or None if processing failed
    """
    if packet is None or config is None:
        return packet
        
    pkt = packet
    
    # Step 1: Extract layers if specified
    if config.extract_at_layer or config.include_layers or config.exclude_layers:
        extracted = extract_layers(
            pkt, 
            config.extract_at_layer, 
            config.include_layers, 
            config.exclude_layers
        )
        if not extracted:
            return None
        pkt = extracted
    
    # Step 2: Repackage if specified
    if config.repackage_template:
        pkt = repackage_payload(pkt, config.repackage_template)
    
    # Step 3: Convert to Scapy object if working with raw data
    if isinstance(pkt, bytes):
        pkt = convert_to_scapy(pkt)
    
    return pkt


# ============================================================================
# Utility Functions for Common Configurations
# ============================================================================

def create_layer_extraction_config(extract_at: str, 
                                  repackage_template: Optional[Packet] = None) -> PacketProcessingConfig:
    """
    Create a configuration for simple layer extraction.
    
    Args:
        extract_at: Layer to extract at
        repackage_template: Optional template for repackaging
        
    Returns:
        Configured PacketProcessingConfig
    """
    return PacketProcessingConfig(
        extract_at_layer=extract_at,
        repackage_template=repackage_template
    )


def create_layer_filter_config(include: Optional[List[str]] = None,
                              exclude: Optional[List[str]] = None) -> PacketProcessingConfig:
    """
    Create a configuration for layer filtering.
    
    Args:
        include: Layers to include (mutually exclusive with exclude)
        exclude: Layers to exclude (mutually exclusive with include)
        
    Returns:
        Configured PacketProcessingConfig
    """
    return PacketProcessingConfig(
        include_layers=include,
        exclude_layers=exclude
    )
