#!/usr/bin/env python3
"""
Socket Type Enum Definition

This module defines the SocketType enum for PacketFuzz campaigns, providing
IDE support, type safety, and auto-completion for socket type options.
"""

from enum import Enum
from typing import Optional

class SocketConfigType(str, Enum):
    """Enumeration of supported socket configuration types for discovery/docs."""
    UDP_SERVER = "udp_server_config"
    TCP_SERVER = "tcp_server_config"
    MANAGED_UDP = "managed_udp_config"
    MANAGED_TCP = "managed_tcp_config"
    CANBUS = "canbus_config"
    RAW_UDP = "raw_udp_config"
    RAW_IP = "raw_ip_config"
    RAW_TCP = "raw_tcp_config"
    RAW_ETHERNET = "raw_ethernet_config"


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
    
    SERVER_TCP = "server_tcp"
    """TCP server socket - binds to port and accepts incoming connections
    
    Requirements:
    - Port must be available for binding
    - Server mode operation
    - Can accept multiple connections
    
    Use case: Server-side fuzzing, protocol testing as server
    """
    
    SERVER_UDP = "server_udp"
    """UDP server socket - binds to port and receives datagrams
    
    Requirements:
    - Port must be available for binding
    - Server mode operation
    - Connectionless datagram reception
    
    Use case: Server-side UDP fuzzing, protocol testing as server
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
            SocketType.CANBUS: ["CAN"],
            SocketType.SERVER_TCP: [],
            SocketType.SERVER_UDP: []
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
            SocketType.CANBUS: "CAN bus - automotive protocols",
            SocketType.SERVER_TCP: "TCP server - accepts incoming connections",
            SocketType.SERVER_UDP: "UDP server - receives datagrams"
        }
        return descriptions.get(self, f"Unknown socket type: {self.value}")

    @classmethod
    def get_raw_socket_types(cls) -> list['SocketType']:
        """Get socket types that require raw socket access."""
        return [
            cls.RAW_ETHERNET,
            cls.RAW_IP,
            cls.RAW_TCP,
            cls.RAW_UDP
        ]

    @classmethod
    def get_listening_socket_types(cls) -> list['SocketType']:
        """Get socket types that support listening for incoming connections."""
        return [
            cls.SERVER_TCP,
            cls.SERVER_UDP
        ]

    def is_listening_type(self) -> bool:
        """Check if this socket type supports listening for incoming connections."""
        return self in self.get_listening_socket_types()


# Backward compatibility
VALID_SOCKET_TYPES = SocketType.get_valid_types()

