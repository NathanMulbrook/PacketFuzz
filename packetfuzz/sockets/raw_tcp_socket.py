#!/usr/bin/env python3
"""
Raw TCP Socket Implementation

Sends packets at Layer 4 (Transport/TCP layer) using raw sockets.
Requires root privileges on most systems.
"""
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING

from .socket_interface import FuzzSocket

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


class RawTCPSocket(FuzzSocket):
    """
    Raw TCP socket implementation for Layer 4 packet sending.
    
    Requirements:
    - Packet must have TCP header (and IP header)
    - Root privileges typically required
    - No connection state management
    
    Use case: TCP protocol testing, connection manipulation
    """

    def open(self) -> "RawTCPSocket":
        """Create and configure raw TCP socket."""
        try:
            # Create raw TCP socket
            s = socket.socket(socket.AF_INET, socket.IPPROTO_TCP)
            
            # Include IP headers in the packet
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            self._sock = s
            return self
        except PermissionError:
            raise PermissionError("Raw TCP sockets require root/administrator privileges")
        except OSError as e:
            raise OSError(f"Failed to create raw TCP socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send raw TCP packet."""
        if not self._sock:
            logging.getLogger(__name__).error("[RawTCPSocket] Socket not open")
            return None
            
        try:
            # Send to target from campaign
            target = getattr(self.campaign, 'target', '127.0.0.1')
            return self._sock.sendto(packet_bytes, (target, 0))
        except Exception as e:
            logging.getLogger(__name__).error(f"[RawTCPSocket] send failed: {e}")
            return None

    def close(self) -> None:
        """Close the raw TCP socket."""
        try:
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[RawTCPSocket] close error: {e}")
