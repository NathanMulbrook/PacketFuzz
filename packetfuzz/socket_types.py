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
    FTP_CLIENT = "ftp_client_config"
    FTP_SERVER = "ftp_server_config"
    TFTP_CLIENT = "tftp_client_config"
    TFTP_SERVER = "tftp_server_config"
    TELNET_CLIENT = "telnet_client_config"
    TELNET_SERVER = "telnet_server_config"
    MODBUS_CLIENT = "modbus_client_config"
    MODBUS_SERVER = "modbus_server_config"


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

    FTP_CLIENT = "ftp_client"
    """FTP client socket - connects to FTP servers for data fuzzing
    
    Requirements:
    - FTP server must be available
    - Supports active and passive modes
    - Uses ftplib for protocol handling
    
    Use case: Fuzzing data sent to FTP servers, file upload fuzzing
    """

    FTP_SERVER = "ftp_server"
    """FTP server socket - accepts FTP client connections
    
    Requirements:
    - Port must be available for binding (default 21)
    - Uses pyftpdlib for server implementation
    - Supports active and passive modes
    
    Use case: Fuzzing data received from FTP clients, server-side fuzzing
    """

    TFTP_CLIENT = "tftp_client"
    """TFTP client socket - connects to TFTP servers for data fuzzing
    
    Requirements:
    - TFTP server must be available
    - Uses tftpy for protocol handling
    - UDP-based protocol (port 69)
    
    Use case: Fuzzing data sent to TFTP servers, file upload fuzzing
    """

    TFTP_SERVER = "tftp_server"
    """TFTP server socket - accepts TFTP client connections
    
    Requirements:
    - Port must be available for binding (default 69)
    - Uses tftpy for server implementation
    - UDP-based protocol
    
    Use case: Fuzzing data received from TFTP clients, server-side fuzzing
    """

    TELNET_CLIENT = "telnet_client"
    """Telnet client socket - connects to Telnet servers for data fuzzing
    
    Requirements:
    - Telnet server must be available
    - Uses telnetlib for protocol handling
    - TCP-based protocol (port 23)
    
    Use case: Fuzzing data sent to Telnet servers, command fuzzing
    """

    TELNET_SERVER = "telnet_server"
    """Telnet server socket - accepts Telnet client connections
    
    Requirements:
    - Port must be available for binding (default 23)
    - Uses custom implementation for server
    - TCP-based protocol
    
    Use case: Fuzzing data received from Telnet clients, server-side fuzzing
    """

    MODBUS_CLIENT = "modbus_client"
    """Modbus client socket - connects to Modbus servers/devices for industrial protocol fuzzing
    
    Requirements:
    - Modbus TCP server/device must be available
    - Uses pymodbus for protocol handling
    - TCP-based protocol (port 502)
    
    Use case: Fuzzing industrial control systems, PLC communication, and SCADA systems
    """

    MODBUS_SERVER = "modbus_server"
    """Modbus server socket - acts as a Modbus server for client application testing
    
    Requirements:
    - Port must be available for binding (default 502)
    - Uses pymodbus for server implementation
    - TCP-based protocol
    
    Use case: Fuzzing Modbus clients, HMIs, and SCADA system responses
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
            SocketType.SERVER_UDP: [],
            SocketType.FTP_CLIENT: [],
            SocketType.FTP_SERVER: [],
            SocketType.TFTP_CLIENT: [],
            SocketType.TFTP_SERVER: [],
            SocketType.TELNET_CLIENT: [],
            SocketType.TELNET_SERVER: [],
            SocketType.MODBUS_CLIENT: [],
            SocketType.MODBUS_SERVER: []
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
            SocketType.SERVER_UDP: "UDP server - receives datagrams",
            SocketType.FTP_CLIENT: "FTP client - connects to FTP servers for data fuzzing",
            SocketType.FTP_SERVER: "FTP server - accepts FTP connections for data fuzzing",
            SocketType.TFTP_CLIENT: "TFTP client - connects to TFTP servers for data fuzzing",
            SocketType.TFTP_SERVER: "TFTP server - accepts TFTP connections for data fuzzing",
            SocketType.TELNET_CLIENT: "Telnet client - connects to Telnet servers for data fuzzing",
            SocketType.TELNET_SERVER: "Telnet server - accepts Telnet connections for data fuzzing",
            SocketType.MODBUS_CLIENT: "Modbus client - connects to Modbus devices for industrial protocol fuzzing",
            SocketType.MODBUS_SERVER: "Modbus server - acts as a Modbus server for client testing"
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
            cls.SERVER_UDP,
            cls.FTP_SERVER,
            cls.TFTP_SERVER,
            cls.TELNET_SERVER,
            cls.MODBUS_SERVER
        ]

    def is_listening_type(self) -> bool:
        """Check if this socket type supports listening for incoming connections."""
        return self in self.get_listening_socket_types()


# Backward compatibility
VALID_SOCKET_TYPES = SocketType.get_valid_types()

