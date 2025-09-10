#!/usr/bin/env python3
"""
Managed UDP Socket Implementation.
Creates and manages standard UDP sockets for datagram transmission.
Uses standard socket operations for connectionless data transmission.
"""
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class ManagedUDPConfig(BaseSocketConfig):
    """Configuration for a managed UDP client socket."""
    target: str = '127.0.0.1'
    port: int = 53


class ManagedUDPSocket(FuzzSocket):
    """
    Managed UDP socket implementation for standard UDP communications.
    
    Features:
    - Standard UDP socket operations
    - Connectionless datagram transmission
    - No root privileges required
    - Optional response receiving
    
    Use case: Application-level protocol fuzzing over UDP
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        # Prefer explicit socket_config when provided
        self.socket_cfg: Optional[ManagedUDPConfig] = (
            self.socket_config if isinstance(self.socket_config, ManagedUDPConfig) else None
        )

    def open(self) -> "ManagedUDPSocket":
        """Create UDP socket."""
        try:
            # Create UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            self._sock = s
            return self
        except (OSError, socket.error) as e:
            raise OSError(f"Failed to create UDP socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send UDP datagram."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        return self._sock.sendto(packet_bytes, (self.socket_config.target, self.socket_config.port))

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive response datagram from UDP socket."""
        if not self._sock:
            return None
            
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            # Receive up to 4KB of data
            data, addr = self._sock.recvfrom(4096)
            logging.getLogger(__name__).debug(f"[ManagedUDPSocket] received {len(data)} bytes from {addr}")
            return data if data else None
        except socket.timeout:
            logging.getLogger(__name__).debug("[ManagedUDPSocket] receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None, iteration: int = 0) -> bytes:
        """
        Prepare packet for PCAP logging with full UDP/IP/Ethernet stack.
        
        For managed UDP sockets, we create a complete protocol stack suitable
        for PCAP analysis with the raw fuzzed bytes as the UDP payload.
        The iteration parameter ensures unique packet identifiers.
        """
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        from scapy.layers.inet import IP, UDP
        from scapy.volatile import RandShort
        import random
        
        target_ip = self.socket_config.target if hasattr(self.socket_config, 'target') else '127.0.0.1'
        target_port = self.socket_config.port if hasattr(self.socket_config, 'port') else 53
        
        # Use iteration for consistent but unique source ports
        base_sport = 49152  # Start of ephemeral port range
        sport = base_sport + (iteration % 16384)  # Keep within ephemeral range
        
        # Create complete UDP/IP/Ethernet packet with fuzzed data as payload
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / \
                   IP(dst=target_ip, src="127.0.0.1") / \
                   UDP(dport=target_port, sport=sport) / Raw(load=raw_bytes)
        
        # Use iteration for unique IP identification
        completed[IP].id = (1 + iteration) % 65536
        
        # Let Scapy recalculate checksums
        try:
            del completed[UDP].chksum
            del completed[IP].chksum
        except (AttributeError, KeyError) as e:
            logger.debug(f"Could not populate UDP fields: {e}")
        
        return bytes(completed)

    def close(self) -> None:
        """Close the UDP socket."""
        super().close()
