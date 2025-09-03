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
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class ManagedTCPConfig(BaseSocketConfig):
    """Configuration for a managed TCP client socket."""
    target: str = '127.0.0.1'
    port: int = 80


class ManagedTCPSocket(FuzzSocket):
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
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: Optional[ManagedTCPConfig] = cfg if isinstance(cfg, ManagedTCPConfig) else None

    def open(self) -> "ManagedTCPSocket":
        """Create and establish TCP connection."""
        try:
            # Create TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Get target and port using standardized config access
            if self.socket_cfg:
                target = self.socket_cfg.target
                port = self.socket_cfg.port
            else:
                target = self.config.get_target('127.0.0.1')
                port = self.config.get_port(80)
            
            # Connect to target
            s.connect((target, port))
            
            self._sock = s
            self.logger.info(f"Connected to {target}:{port}")
            return self
        except Exception as e:
            error_msg = f"Failed to create/connect TCP socket to {target}:{port}"
            self.logger.error(error_msg, e)
            raise OSError(f"{error_msg}: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send data over TCP connection."""
        if not self._sock:
            self.logger.error("Socket not open")
            return None
            
        try:
            return self._sock.send(packet_bytes)
        except Exception as e:
            self.logger.error("send failed", e)
            return None

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
        except Exception as e:
            self.logger.error("receive failed", e)
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def close(self) -> None:
        """Close the TCP connection."""
        try:
            if self._sock:
                # Graceful shutdown
                self._sock.shutdown(socket.SHUT_RDWR)
            super().close()
        except Exception as e:
            self.logger.warning(f"close error: {e}")
