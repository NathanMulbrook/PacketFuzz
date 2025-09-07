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

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare packet for PCAP logging with full TCP/IP/Ethernet stack.
        
        For managed TCP sockets, we create a complete protocol stack suitable
        for PCAP analysis with the raw fuzzed bytes as the TCP payload.
        """
        from scapy.layers.l2 import Ether, Raw
        from scapy.layers.inet import IP, TCP
        from scapy.volatile import RandInt, RandShort
        import random
        
        target_ip = self.config.get_target('127.0.0.1')
        target_port = self.config.get_port(80)
        sport = random.randint(49152, 65535)  # Ephemeral port range
        
        # Create complete TCP/IP/Ethernet packet with fuzzed data as payload
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / \
                   IP(dst=target_ip, src="127.0.0.1") / \
                   TCP(dport=target_port, sport=sport) / Raw(load=raw_bytes)
        
        # Populate connection fields for clean PCAP output
        try:
            completed[TCP].seq = RandInt()
            del completed[TCP].chksum  # Let Scapy recalculate
            completed[IP].id = RandShort()
            del completed[IP].chksum  # Let Scapy recalculate
        except Exception as e:
            self.logger.debug(f"Could not populate connection fields: {e}")
        
        return bytes(completed)

    def close(self) -> None:
        """Close the TCP connection."""
        try:
            if self._sock:
                # Graceful shutdown
                self._sock.shutdown(socket.SHUT_RDWR)
            super().close()
        except Exception as e:
            self.logger.warning(f"close error: {e}")
