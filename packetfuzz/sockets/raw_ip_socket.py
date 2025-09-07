#!/usr/bin/env python3
"""
Raw IP Socket Implementation

Sends packets at Layer 3 (Network/IP layer) using raw IP sockets.
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
class RawIPConfig(BaseSocketConfig):
    """Optional config for raw IP socket targeting (when needed)."""
    target: str = '127.0.0.1'


class RawIPSocket(FuzzSocket):
    """
    Raw IP socket implementation for Layer 3 packet sending.
    
    Requirements:
    - Packet must have IP header
    - Root privileges typically required
    - OS handles Ethernet framing
    
    Use case: IP-level protocol testing, custom IP protocols
    """

    def open(self) -> "RawIPSocket":
        """Create and configure raw IP socket."""
        try:
            # Create raw IP socket
            s = socket.socket(socket.AF_INET, socket.IPPROTO_RAW)
            
            # Include IP headers in the packet
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            self._sock = s
            return self
        except PermissionError:
            raise PermissionError("Raw IP sockets require root/administrator privileges")
        except OSError as e:
            raise OSError(f"Failed to create raw IP socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send raw IP packet."""
        if not self._sock:
            raise RuntimeError("Socket not open")

        return self._sock.sendto(packet_bytes, (self.socket_config.target, 0))

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare packet for PCAP logging for raw IP sockets.
        
        Raw IP packets already contain complete IP headers, so we just need to 
        add Ethernet framing for PCAP compatibility.
        """
        from scapy.layers.l2 import Ether
        
        # Add Ethernet frame around the raw IP packet
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / raw_bytes
        return bytes(completed)

    def close(self) -> None:
        """Close the raw IP socket."""
        super().close()
