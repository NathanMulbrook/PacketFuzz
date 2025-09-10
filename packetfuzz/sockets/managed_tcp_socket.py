#!/usr/bin/env python3
"""
Managed TCP Socket Implementation

ates and manages standard TCP connections with automatic handshake handling.
Uses standard socket operations for reliable data transmission.
"""
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig
from ..socket_types import SocketType

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class ManagedTCPConfig(BaseSocketConfig):
    """Configuration for a managed TCP client socket."""
    target: str = '127.0.0.1'
    port: int = 80


class ManagedTCPSocket(FuzzSocket):
    SOCKET_TYPE = SocketType.MANAGED_TCP
    """
    Managed TCP socket implementation for standard TCP connections.
    
    Features:
    - Automatic TCP handshake
    - Connection state management
    - Standard socket operations
    - No root privileges required
    
    Use case: Application-level protocol fuzzing over TCP
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        self.socket_cfg: Optional[ManagedTCPConfig] = self.socket_config if isinstance(self.socket_config, ManagedTCPConfig) else None

    def open(self) -> "ManagedTCPSocket":
        """Create and establish TCP connection."""
        # Create TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        # Connect to target
        s.connect((self.socket_config.target, self.socket_config.port))
        
        self._sock = s
        self.logger.info(f"Connected to {self.socket_config.target}:{self.socket_config.port}")
        return self

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send data over TCP connection."""
        if not self._sock:
            raise RuntimeError("Socket not open")
            
        return self._sock.send(packet_bytes)

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive response data from TCP connection."""
        if not self._sock:
            return None
            
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            # Receive up to 4KB of data
            data = self._sock.recv(4096)
            return data if data else None
        except socket.timeout:
            self.logger.debug("receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None, iteration: int = 0) -> bytes:
        """
        Prepare packet for PCAP logging with full TCP/IP/Ethernet stack.
        
        For managed TCP sockets, we create a complete protocol stack suitable
        for PCAP analysis with the raw fuzzed bytes as the TCP payload.
        The iteration parameter ensures proper sequence number progression.
        """
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        from scapy.layers.inet import IP, TCP
        import random
        
        target_ip = self.socket_config.target if hasattr(self.socket_config, 'target') else '127.0.0.1'
        target_port = self.socket_config.port if hasattr(self.socket_config, 'port') else 80
        
        # Use iteration for consistent but unique source ports
        base_sport = 49152  # Start of ephemeral port range  
        sport = base_sport + (iteration % 16384)  # Keep within ephemeral range
        
        # Create complete TCP/IP/Ethernet packet with fuzzed data as payload
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / \
                   IP(dst=target_ip, src="127.0.0.1") / \
                   TCP(dport=target_port, sport=sport) / Raw(load=raw_bytes)
        
        # Use iteration for proper sequence number progression and unique IP IDs
        payload_size = len(raw_bytes)
        base_seq = 1000  # Starting sequence number
        completed[TCP].seq = base_seq + (iteration * max(payload_size, 1))
        completed[IP].id = (1 + iteration) % 65536
        
        # Let Scapy recalculate checksums
        try:
            del completed[TCP].chksum
            del completed[IP].chksum
        except (AttributeError, KeyError) as e:
            logging.debug(f"Could not populate connection fields: {e}")
        
        return bytes(completed)

    def close(self) -> None:
        """Close the TCP connection."""
        try:
            if self._sock:
                # Graceful shutdown
                self._sock.shutdown(socket.SHUT_RDWR)
            super().close()
        except (ConnectionError, OSError):
            self.logger.warning(f"Socket already closed or connection lost during close")
        except Exception as e:
            self.logger.warning(f"Unexpected error during close: {e}")
            raise  # Re-raise unexpected errors
