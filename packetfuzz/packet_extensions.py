#!/usr/bin/env python3
"""
Simplified Scapy Packet Extensions for Embedded Fuzzing Configuration

This module provides a simpler approach that doesn't interfere with Scapy's 
internal attribute resolution mechanism.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field

from scapy.packet import Packet
from scapy.fields import Field


@dataclass
class FieldFuzzConfig:
    """Configuration for fuzzing a specific field"""
    dictionary: List[str] = field(default_factory=list)
    default_values: List[Any] = field(default_factory=list) 
    fuzz_weight: float = 1.0
    description: str = ""
    
    def __post_init__(self):
        """Ensure dictionary and default_values are lists"""
        if isinstance(self.dictionary, str):
            self.dictionary = [self.dictionary]
        if not isinstance(self.default_values, list):
            self.default_values = [self.default_values] if self.default_values is not None else []

#TODO switch things internally over to this, rather than passing around separate config items, store in packet directly.
#This stores similar information to FuzzField, is it possible to merge these?
@dataclass
class PacketFuzzConfig:
    """
    Configuration for fuzzing an entire packet or layer.
    Includes all options that affect fuzzing logic, but not campaign-level execution settings.
    Advanced fields support exclusion, mutator weighting, resolved field configs, and provenance.
    """
    dictionary: List[str] = field(default_factory=list)
    mutators: List[str] = field(default_factory=list)
    fuzz_weight: float = 1.0
    use_scapy_fuzz: bool = False
    scapy_fuzz_weight: float = 0.1
    dictionary_only_weight: float = 0.0
    field_matching: Optional[dict] = None  # Resolved field mapping for this packet/layer
    field_configs: Optional[dict] = None   # Resolved field configs for this packet/layer
    mutator_weights: Optional[dict] = None # Per-mutator weighting
    excluded: bool = False                # Exclude this packet/layer from fuzzing
    mode: Optional[str] = None            # Fuzzing mode (e.g., 'static', 'hybrid', etc.)
    source_campaign: Optional[str] = None # Provenance/debugging
    description: str = ""
    
    def __post_init__(self):
        if isinstance(self.dictionary, str):
            self.dictionary = [self.dictionary]
        if isinstance(self.mutators, str):
            self.mutators = [self.mutators]


class FuzzConfigRegistry:
    """
    Global registry for fuzzing configurations attached to packet instances.
    Uses object IDs to avoid hashability issues.
    """
    
    def __init__(self):
        # Use object IDs as keys since Scapy packets are not hashable
        self._packet_configs: Dict[int, PacketFuzzConfig] = {}
        self._field_configs: Dict[int, Dict[str, FieldFuzzConfig]] = {}
        # Keep track of packet IDs for cleanup (no weak references for now)
        self._packet_ids: set[int] = set()
    
    def _get_packet_id(self, packet: Packet) -> int:
        """Get packet ID"""
        packet_id = id(packet)
        self._packet_ids.add(packet_id)
        return packet_id
    
    def set_packet_config(self, packet: Packet, config: PacketFuzzConfig) -> None:
        """Set fuzzing configuration for an entire packet"""
        packet_id = self._get_packet_id(packet)
        self._packet_configs[packet_id] = config
    
    def get_packet_config(self, packet: Packet) -> Optional[PacketFuzzConfig]:
        """Get fuzzing configuration for a packet"""
        packet_id = self._get_packet_id(packet)
        return self._packet_configs.get(packet_id)
    
    def set_field_config(self, packet: Packet, field_name: str, config: FieldFuzzConfig) -> None:
        """Set fuzzing configuration for a specific field in a packet"""
        packet_id = self._get_packet_id(packet)
        if packet_id not in self._field_configs:
            self._field_configs[packet_id] = {}
        self._field_configs[packet_id][field_name] = config
    
    def get_field_config(self, packet: Packet, field_name: str) -> Optional[FieldFuzzConfig]:
        """Get fuzzing configuration for a specific field in a packet"""
        packet_id = self._get_packet_id(packet)
        if packet_id in self._field_configs:
            return self._field_configs[packet_id].get(field_name)
        return None
    
    def get_all_field_configs(self, packet: Packet) -> Dict[str, FieldFuzzConfig]:
        """Get all field configurations for a packet"""
        packet_id = self._get_packet_id(packet)
        return self._field_configs.get(packet_id, {})
    
    def clear_packet_configs(self, packet: Packet) -> None:
        """Clear all configurations for a packet"""
        packet_id = self._get_packet_id(packet)
        self._packet_configs.pop(packet_id, None)
        self._field_configs.pop(packet_id, None)
        self._packet_ids.discard(packet_id)


# Global registry instance
_fuzz_config_registry = FuzzConfigRegistry()


class FieldFuzzProxy:
    """
    Proxy object that provides field fuzzing configuration interface.
    """
    
    def __init__(self, packet: Packet, field_name: str):
        self._packet = packet
        self._field_name = field_name
    
    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith('_'):
            super().__setattr__(name, value)
            return
        
        # Get or create field config
        config = _fuzz_config_registry.get_field_config(self._packet, self._field_name)
        if config is None:
            config = FieldFuzzConfig()
            _fuzz_config_registry.set_field_config(self._packet, self._field_name, config)
        
        # Set the configuration attribute
        if hasattr(config, name):
            setattr(config, name, value)
        else:
            raise AttributeError(f"FieldFuzzConfig has no attribute '{name}'")
    
    def __getattr__(self, name: str) -> Any:
        config = _fuzz_config_registry.get_field_config(self._packet, self._field_name)
        if config is None:
            config = FieldFuzzConfig()
            _fuzz_config_registry.set_field_config(self._packet, self._field_name, config)
        
        if hasattr(config, name):
            return getattr(config, name)
        else:
            raise AttributeError(f"FieldFuzzConfig has no attribute '{name}'")
    
    def get_value(self) -> Any:
        """Get the actual field value"""
        return getattr(self._packet, self._field_name)


class PacketFuzzProxy:
    """
    Proxy object for packet-level fuzzing configuration.
    """
    
    def __init__(self, packet: Packet):
        self._packet = packet
    
    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith('_'):
            super().__setattr__(name, value)
            return
        
        # Get or create packet config
        config = _fuzz_config_registry.get_packet_config(self._packet)
        if config is None:
            config = PacketFuzzConfig()
            _fuzz_config_registry.set_packet_config(self._packet, config)
        
        # Set the configuration attribute
        if hasattr(config, name):
            setattr(config, name, value)
        else:
            raise AttributeError(f"PacketFuzzConfig has no attribute '{name}'")
    
    def __getattr__(self, name: str) -> Any:
        config = _fuzz_config_registry.get_packet_config(self._packet)
        if config is None:
            config = PacketFuzzConfig()
            _fuzz_config_registry.set_packet_config(self._packet, config)
        
        if hasattr(config, name):
            return getattr(config, name)
        else:
            raise AttributeError(f"PacketFuzzConfig has no attribute '{name}'")


def install_packet_extensions():
    """
    Install fuzzing extensions into Scapy Packet classes.
    
    Uses method injection instead of monkey patching __getattr__.
    """
    
    # Add utility methods to Packet class
    def get_fuzz_config(self) -> Optional[PacketFuzzConfig]:
        """Get packet-level fuzzing configuration"""
        return _fuzz_config_registry.get_packet_config(self)
    
    def get_field_fuzz_config(self, field_name: str) -> Optional[FieldFuzzConfig]:
        """Get field-level fuzzing configuration"""
        return _fuzz_config_registry.get_field_config(self, field_name)
    
    def get_all_field_fuzz_configs(self) -> Dict[str, FieldFuzzConfig]:
        """Get all field-level fuzzing configurations for this packet"""
        return _fuzz_config_registry.get_all_field_configs(self)
    
    def clear_fuzz_configs(self) -> None:
        """Clear all fuzzing configurations for this packet"""
        _fuzz_config_registry.clear_packet_configs(self)
    
    def has_fuzz_config(self) -> bool:
        """Check if packet has any fuzzing configuration"""
        return (self.get_fuzz_config() is not None or 
                len(self.get_all_field_fuzz_configs()) > 0)
    
    def fuzz_config(self) -> PacketFuzzProxy:
        """Get fuzzing configuration proxy for packet"""
        return PacketFuzzProxy(self)
    
    def field_fuzz(self, field_name: str) -> FieldFuzzProxy:
        """Get fuzzing configuration proxy for a field"""
        return FieldFuzzProxy(self, field_name)
    
    # Add methods to Packet class
    Packet.get_fuzz_config = get_fuzz_config  # type: ignore[attr-defined]
    Packet.get_field_fuzz_config = get_field_fuzz_config  # type: ignore[attr-defined]
    Packet.get_all_field_fuzz_configs = get_all_field_fuzz_configs  # type: ignore[attr-defined]
    Packet.clear_fuzz_configs = clear_fuzz_configs  # type: ignore[attr-defined]
    Packet.has_fuzz_config = has_fuzz_config  # type: ignore[attr-defined]
    Packet.fuzz_config = fuzz_config  # type: ignore[attr-defined]
    Packet.field_fuzz = field_fuzz  # type: ignore[attr-defined]


def uninstall_packet_extensions():
    """
    Remove fuzzing extensions from Scapy Packet classes.
    """
    # Remove added methods
    methods_to_remove = [
        'get_fuzz_config', 'get_field_fuzz_config', 'get_all_field_fuzz_configs',
        'clear_fuzz_configs', 'has_fuzz_config', 'fuzz_config', 'field_fuzz'
    ]
    
    for method_name in methods_to_remove:
        if hasattr(Packet, method_name):
            delattr(Packet, method_name)


def apply_packet_extensions():
    """
    Apply fuzzing extensions to Scapy Packet classes.
    
    This function provides a clean interface for enabling the extensions.
    """
    install_packet_extensions()


# Auto-install extensions when module is imported
install_packet_extensions()
