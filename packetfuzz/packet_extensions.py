#!/usr/bin/env python3
"""
Simplified Scapy Packet Extensions for Embedded Fuzzing Configuration

This module provides a simpler approach that doesn't interfere with Scapy's 
internal attribute resolution mechanism.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from scapy.fields import Field
from scapy.packet import Packet


@dataclass
class FieldFuzzConfig:
    """Configuration for fuzzing a specific field."""
    dictionary: List[str] = field(default_factory=list)
    default_values: List[Any] = field(default_factory=list) 
    fuzz_weight: float = 1.0
    description: str = ""
    
    def __post_init__(self):
        """Post-initialization setup for packet extensions."""
        """Ensure dictionary and default_values are lists."""
        if isinstance(self.dictionary, str):
            self.dictionary = [self.dictionary]
        if not isinstance(self.default_values, list):
            self.default_values = [self.default_values] if self.default_values is not None else []



class FuzzConfigRegistry:
    """
    Registry for field-level fuzzing configurations attached to packet instances.
    Uses object IDs to avoid hashability issues.
    """
    
    def __init__(self):
        # Use object IDs as keys since Scapy packets are not hashable
        self._field_configs: Dict[int, Dict[str, FieldFuzzConfig]] = {}
        # Keep track of packet IDs for cleanup (no weak references for now)
        self._packet_ids: set[int] = set()
    
    def _get_packet_id(self, packet: Packet) -> int:
        """Get packet ID"""
        packet_id = id(packet)
        self._packet_ids.add(packet_id)
        return packet_id
    
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
        self._field_configs.pop(packet_id, None)
        self._packet_ids.discard(packet_id)


_fuzz_config_registry = FuzzConfigRegistry()


class FieldFuzzProxy:
    """
    Proxy object that provides field fuzzing configuration interface.
    """
    
    def __init__(self, packet: Packet, field_name: str):
        self._packet = packet
        self._field_name = field_name
    
    def __setattr__(self, name: str, value: Any) -> None:
        """Set attribute with custom handling for packet extensions."""
        if name.startswith('_'):
            super().__setattr__(name, value)
            return
        
        config = _fuzz_config_registry.get_field_config(self._packet, self._field_name)
        if config is None:
            config = FieldFuzzConfig()
            _fuzz_config_registry.set_field_config(self._packet, self._field_name, config)
        
        if hasattr(config, name):
            setattr(config, name, value)
        else:
            raise AttributeError(f"FieldFuzzConfig has no attribute '{name}'")
    
    def __getattr__(self, name: str) -> Any:
        """Get attribute with custom handling for packet extensions."""
        config = _fuzz_config_registry.get_field_config(self._packet, self._field_name)
        if config is None:
            config = FieldFuzzConfig()
            _fuzz_config_registry.set_field_config(self._packet, self._field_name, config)
        
        if hasattr(config, name):
            return getattr(config, name)
        else:
            raise AttributeError(f"FieldFuzzConfig has no attribute '{name}'")




def install_packet_extensions():
    """
    Install field-level fuzzing extensions into Scapy Packet classes.
    
    Uses method injection for field configuration only.
    """
    
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
        """Check if packet has any field-level fuzzing configuration"""
        return len(self.get_all_field_fuzz_configs()) > 0
    
    def field_fuzz(self, field_name: str) -> FieldFuzzProxy:
        """Get fuzzing configuration proxy for a field"""
        return FieldFuzzProxy(self, field_name)
    
    Packet.get_field_fuzz_config = get_field_fuzz_config  # type: ignore[attr-defined]
    Packet.get_all_field_fuzz_configs = get_all_field_fuzz_configs  # type: ignore[attr-defined]
    Packet.clear_fuzz_configs = clear_fuzz_configs  # type: ignore[attr-defined]
    Packet.has_fuzz_config = has_fuzz_config  # type: ignore[attr-defined]
    Packet.field_fuzz = field_fuzz  # type: ignore[attr-defined]


install_packet_extensions()
