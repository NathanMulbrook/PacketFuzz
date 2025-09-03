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

from .socket_interface import FuzzSocket

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


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
            logging.getLogger(__name__).error("[RawIPSocket] Socket not open")
            return None
            
        try:
            # Send to target from campaign
            target = getattr(self.campaign, 'target', '127.0.0.1')
            return self._sock.sendto(packet_bytes, (target, 0))
        except Exception as e:
            logging.getLogger(__name__).error(f"[RawIPSocket] send failed: {e}")
            return None

    def close(self) -> None:
        """Close the raw IP socket."""
        try:
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[RawIPSocket] close error: {e}")
