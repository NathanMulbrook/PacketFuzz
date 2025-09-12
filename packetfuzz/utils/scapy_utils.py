
import logging
from typing import Optional, Any, List, Set
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def get_packet_summary(packet: Optional[Packet]) -> str:
    """Get packet summary - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot get summary from None packet")
    
    # Use Scapy's summary method if available, otherwise str()
    if hasattr(packet, 'summary'):
        return packet.summary()
    return str(packet)


def get_packet_size(packet: Optional[Packet]) -> int:
    """Get packet size - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot get size from None packet")
    
    return len(packet)



def packet_field_access(packet: Packet, layer_name: str, field_name: str, default: Any = None) -> Any:
    """Access packet field value - fails hard if layer/field doesn't exist (unless default provided)."""
    if packet is None:
        raise ValueError("Cannot access field from None packet")
    if not layer_name:
        raise ValueError("Layer name must be a non-empty string")
    if not field_name:
        raise ValueError("Field name must be a non-empty string")
    
    
    layer = packet[layer_name]  # Let this raise KeyError if layer doesn't exist
    if not hasattr(layer, field_name):
        if default is not None:
            return default
        raise AttributeError(f"Layer {layer_name} has no field {field_name}")
    
    return getattr(layer, field_name)


def get_payload(packet: Optional[Packet]) -> Optional[Packet]:
    """Get packet payload - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot get payload from None packet")
    return packet.payload


def packet_to_str(packet: Optional[Packet]) -> str:
    """Convert packet to string - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot convert None packet to string")
    return str(packet)


##Layer Related Functions


def get_scapy_layer_names() -> Set[str]:
    """
    Get only real Scapy packet layer names (excludes fuzzing categories).
    
    Returns:
        Set of all Scapy layer class names in scapy
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
        # Fail hard: inability to enumerate Scapy layers is a configuration/runtime error
        raise RuntimeError(f"Error getting Scapy layer names: {e}")
    
    return scapy_layers


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
        raise ValueError("Cannot extract layer names from None or empty input")
    
    # Normalize to iterable (handle single packet, lists, PacketList)
    from scapy.plist import PacketList
    if not isinstance(packets, (list, tuple, PacketList)):
        packets = [packets]
    
    # Extract all unique layer names using Scapy's layers() method
    return {cls.__name__ for packet in packets if packet for cls in packet.layers()}



def get_layer_by_name(packet: Optional[Packet], layer_name: str) -> Optional[Packet]:
    """Get specific layer from packet - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot get layer from None packet")
    if not layer_name:
        raise ValueError("Layer name must be a non-empty string")
    
    # Try Scapy's built-in method first
    if hasattr(packet, 'getlayer'):
        return packet.getlayer(layer_name)
    
    # Fallback to manual traversal
    current = packet
    while current:
        if get_layer_name(current) == layer_name:
            return current
        current = get_payload(current) if current else None
    
    return None


def has_layer(packet: Optional[Packet], layer_name: str) -> bool:
    """Check if packet has a specific layer - fails hard if packet is invalid."""
    if packet is None:
        raise ValueError("Cannot check layers in None packet")
    if not layer_name:
        raise ValueError("Layer name must be a non-empty string")
    
    # Use Scapy's built-in method if available
    if hasattr(packet, 'haslayer'):
        return packet.haslayer(layer_name)
    
    # Fallback to manual traversal
    current = packet
    while current:
        if get_layer_name(current) == layer_name:
            return True
        current = get_payload(current) if current else None
    
    return False

def get_layer_name(layer: Any) -> str:
    """Get layer name - fails hard if layer is invalid."""
    if layer is None:
        raise ValueError("Cannot get layer name from None")
    return layer.__class__.__name__


##Field related functions


def calculate_layer_depth_below(layer) -> int:
    """
    Calculate the depth of layers below the current layer.
    
    Args:
        layer: The current layer to calculate depth from
        
    Returns:
        int: Number of layers below the current layer (0 = innermost, 1+ = outer layers)
    """
    if layer is None:
        raise ValueError("Cannot calculate depth from None layer")
    
    depth_below = 0
    cursor = layer
    while hasattr(cursor, 'payload') and cursor.payload and cursor.payload.__class__.__name__ != 'NoPayload':
        depth_below += 1
        cursor = cursor.payload
    return depth_below


def find_field_descriptor(packet, field_name: str):
    """
    Look up field descriptor by name in packet's field definitions.
    
    Args:
        packet: The packet object
        field_name: Name of the field to find
        
    Returns:
        Field descriptor object if found, None otherwise
    """
    if packet is None:
        raise ValueError("Cannot find field descriptor in None packet")
    if not field_name:
        raise ValueError("Field name must be a non-empty string")
    
    for field_desc in packet.__class__.fields_desc:
        if field_desc.name == field_name:
            return field_desc
    return None

