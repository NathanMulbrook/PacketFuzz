#!/usr/bin/env python3
"""
Socket Type Enum Definition

This module defines the SocketType enum for PacketFuzz campaigns, providing
IDE support, type safety, and auto-completion for socket type options.
"""

from enum import Enum
from typing import Optional


class SocketType(str, Enum):
    """
    Socket types supported by PacketFuzz campaigns.
    
    This enum provides IDE auto-completion and type safety for socket type selection.
    Each socket type determines how packets are sent and what layer validation is performed.
    
    Attributes:
        RAW_ETHERNET: Raw Ethernet socket - requires Ethernet headers
        RAW_IP: Raw IP socket - requires IP headers  
        RAW_TCP: Raw TCP socket - requires TCP headers
        RAW_UDP: Raw UDP socket - requires UDP headers
        MANAGED_TCP: Managed TCP connection - handles TCP handshake
        MANAGED_UDP: Managed UDP connection - handles UDP sockets
        CANBUS: CAN bus socket - for automotive protocols
    """
    
    RAW_ETHERNET = "raw_ethernet"
    """Raw Ethernet socket - sends packets at Layer 2 (Data Link)
    
    Requirements:
    - Packet must have Ethernet header
    - Root privileges typically required
    - Direct hardware access
    
    Use case: Low-level network testing, custom protocols
    """
    
    RAW_IP = "raw_ip" 
    """Raw IP socket - sends packets at Layer 3 (Network)
    
    Requirements:
    - Packet must have IP header
    - Root privileges typically required
    - OS handles Ethernet framing
    
    Use case: IP-level protocol testing, custom IP protocols
    """
    
    RAW_TCP = "raw_tcp"
    """Raw TCP socket - sends packets at Layer 4 (Transport)
    
    Requirements:
    - Packet must have TCP header
    - Root privileges typically required
    - No connection state management
    
    Use case: TCP protocol testing, connection manipulation
    """
    
    RAW_UDP = "raw_udp"
    """Raw UDP socket - sends packets at Layer 4 (Transport)
    
    Requirements:
    - Packet must have UDP header
    - Root privileges typically required
    - Connectionless protocol
    
    Use case: UDP protocol testing, stateless communication
    """
    
    MANAGED_TCP = "managed_tcp"
    """Managed TCP connection - establishes proper TCP connection
    
    Requirements:
    - Target must accept TCP connections
    - Handles TCP handshake automatically
    - Connection state managed
    
    Use case: Application-level testing over TCP
    """
    
    MANAGED_UDP = "managed_udp"
    """Managed UDP connection - uses standard UDP sockets
    
    Requirements:
    - Target UDP port should be open
    - No connection establishment
    - Standard socket operations
    
    Use case: Application-level testing over UDP
    """
    
    CANBUS = "canbus"
    """CAN bus socket - for automotive Controller Area Network
    
    Requirements:
    - CAN interface available
    - Specialized hardware/software
    - Automotive protocol support
    
    Use case: Automotive protocol testing, ECU fuzzing
    """

    @classmethod
    def get_valid_types(cls) -> list[str]:
        """Get list of all valid socket type strings."""
        return [socket_type.value for socket_type in cls]

    @classmethod
    def from_string(cls, value: Optional[str]) -> Optional['SocketType']:
        """Convert string to SocketType enum, return None if invalid."""
        if value is None:
            return None
        try:
            return cls(value)
        except ValueError:
            return None

    def requires_root(self) -> bool:
        """Check if this socket type typically requires root privileges."""
        return self in [
            SocketType.RAW_ETHERNET,
            SocketType.RAW_IP, 
            SocketType.RAW_TCP,
            SocketType.RAW_UDP
        ]

    def requires_headers(self) -> list[str]:
        """Get list of required packet headers for this socket type."""
        header_requirements = {
            SocketType.RAW_ETHERNET: ["Ether"],
            SocketType.RAW_IP: ["IP"],
            SocketType.RAW_TCP: ["TCP"], 
            SocketType.RAW_UDP: ["UDP"],
            SocketType.MANAGED_TCP: [],
            SocketType.MANAGED_UDP: [],
            SocketType.CANBUS: ["CAN"]
        }
        return header_requirements.get(self, [])

    def get_description(self) -> str:
        """Get human-readable description of the socket type."""
        descriptions = {
            SocketType.RAW_ETHERNET: "Raw Ethernet (Layer 2) - requires Ethernet headers",
            SocketType.RAW_IP: "Raw IP (Layer 3) - requires IP headers",
            SocketType.RAW_TCP: "Raw TCP (Layer 4) - requires TCP headers", 
            SocketType.RAW_UDP: "Raw UDP (Layer 4) - requires UDP headers",
            SocketType.MANAGED_TCP: "Managed TCP connection - handles handshake",
            SocketType.MANAGED_UDP: "Managed UDP connection - standard sockets",
            SocketType.CANBUS: "CAN bus - automotive protocols"
        }
        return descriptions.get(self, f"Unknown socket type: {self.value}")


# Backward compatibility
VALID_SOCKET_TYPES = SocketType.get_valid_types()

