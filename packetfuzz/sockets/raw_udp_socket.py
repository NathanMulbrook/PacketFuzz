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

from .socket_interface import FuzzSocket

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


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
            logging.getLogger(__name__).error("[RawUDPSocket] Socket not open")
            return None
            
        try:
            # Send to target from campaign
            target = getattr(self.campaign, 'target', '127.0.0.1')
            return self._sock.sendto(packet_bytes, (target, 0))
        except Exception as e:
            logging.getLogger(__name__).error(f"[RawUDPSocket] send failed: {e}")
            return None

    def close(self) -> None:
        """Close the raw UDP socket."""
        try:
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[RawUDPSocket] close error: {e}")
