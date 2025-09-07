#!/usr/bin/env python3
"""
CAN Bus Socket Implementation

Sends packets over CAN bus interface using SocketCAN (Linux).
Requires CAN interface configuration and appropriate privileges.
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
class CANBusConfig(BaseSocketConfig):
    """Configuration for a CAN bus socket."""
    interface: str = 'vcan0'


class CANBusSocket(FuzzSocket):
    """
    CAN bus socket implementation for automotive protocol fuzzing.
    
    Requirements:
    - Linux SocketCAN interface
    - CAN interface must be configured (e.g., vcan0, can0)
    - Packet should be CAN frame format
    
    Use case: Automotive protocol testing, CAN bus fuzzing
    """

    def open(self) -> "CANBusSocket":
        """Create and bind CAN socket."""
        try:
            # Import socket constants for CAN
            import socket
            
            # Check if CAN support is available
            if not hasattr(socket, 'CAN_RAW'):
                raise OSError("CAN socket support not available on this system")
            
            # Create CAN socket
            s = socket.socket(socket.AF_CAN, socket.CAN_RAW)
                    
            # Bind to CAN interface
            s.bind((self.socket_config.interface,))
            
            self._sock = s
            return self
        except ImportError:
            raise OSError("CAN socket support not available - missing SocketCAN")
        except Exception as e:
            raise OSError(f"Failed to create/bind CAN socket: {e}")

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send CAN frame."""
        if not self._sock:
            raise RuntimeError("Socket not open")
            
        return self._sock.send(packet_bytes)



    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive CAN frame from bus."""
        if not self._sock:
            return None
            
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            # Receive CAN frame (max 16 bytes for standard CAN frame)
            data = self._sock.recv(16)
            return data if data else None
        except socket.timeout:
            logging.getLogger(__name__).debug("[CANBusSocket] receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare packet for PCAP logging for CAN bus sockets.
        
        CAN frames have a specific format, so we create a minimal Ethernet frame
        with the raw CAN data as payload for PCAP compatibility.
        """
        from scapy.layers.l2 import Ether, Raw
        
        # Create Ethernet frame with CAN data as payload
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / Raw(load=raw_bytes)
        return bytes(completed)

    def close(self) -> None:
        """Close the CAN socket."""
        super().close()
