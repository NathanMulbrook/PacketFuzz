#!/usr/bin/env python3
"""
Managed UDP Socket ImplementatioCreates and manages standard UDP sockets for datagram transmission.
Uses standard socket operations for connectionless data transmission.
"""
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING

from .socket_interface import FuzzSocket

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


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

    def open(self) -> "ManagedUDPSocket":
        """Create UDP socket."""
        try:
            # Create UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            self._sock = s
            return self
        except Exception as e:
            raise OSError(f"Failed to create UDP socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send UDP datagram."""
        if not self._sock:
            logging.getLogger(__name__).error("[ManagedUDPSocket] Socket not open")
            return None
            
        try:
            # Get target and port from campaign
            target = getattr(self.campaign, 'target', '127.0.0.1')
            port = getattr(self.campaign, 'port', 53)  # Default to DNS port
            
            return self._sock.sendto(packet_bytes, (target, port))
        except Exception as e:
            logging.getLogger(__name__).error(f"[ManagedUDPSocket] send failed: {e}")
            return None

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
        except Exception as e:
            logging.getLogger(__name__).error(f"[ManagedUDPSocket] receive failed: {e}")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def close(self) -> None:
        """Close the UDP socket."""
        try:
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[ManagedUDPSocket] close error: {e}")
