#!/usr/bin/env python3
"""
Raw UDP Socket Implementation

Sends packets at Layer 4 (Transport/UDP layer) using raw sockets.
Requires root privileges on most systems.
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
class RawUDPConfig(BaseSocketConfig):
    """Optional config for raw UDP socket targeting (when needed)."""
    target: str = '127.0.0.1'
    port: int = 53


class RawUDPSocket(FuzzSocket):
    """
    Raw UDP socket implementation for Layer 4 packet sending.
    
    Requirements:
    - Packet must have UDP header (and IP header)
    - Root privileges typically required
    - No connection state management
    
    Use case: UDP protocol testing, stateless packet manipulation
    """

    def open(self) -> "RawUDPSocket":
        """Create and configure raw UDP socket."""
        try:
            # Create raw UDP socket
            s = socket.socket(socket.AF_INET, socket.IPPROTO_UDP)
            
            # Include IP headers in the packet
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            self._sock = s
            return self
        except PermissionError:
            raise PermissionError("Raw UDP sockets require root/administrator privileges")
        except OSError as e:
            raise OSError(f"Failed to create raw UDP socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send raw UDP packet."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        return self._sock.sendto(packet_bytes, (self.socket_config.target, self.socket_config.port))

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare packet for PCAP logging for raw UDP sockets.
        
        Raw UDP packets already contain complete UDP/IP headers, so we just need to 
        add Ethernet framing for PCAP compatibility.
        """
        from scapy.layers.l2 import Ether
        
        # Add Ethernet frame around the raw UDP/IP packet
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / raw_bytes
        return bytes(completed)

    def close(self) -> None:
        """Close the raw UDP socket."""
        super().close()
