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

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None, iteration: int = 0) -> bytes:
        """
        Prepare packet for PCAP logging for raw IP sockets.
        
        Raw IP packets already contain complete IP headers. When possible, we use the 
        original packet structure to preserve protocol layering, otherwise we parse 
        the raw bytes. Then we add Ethernet framing for PCAP compatibility.
        The iteration parameter allows for unique identifiers across packets.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP
        from scapy.packet import Raw
        import copy
        
        try:
            # Prefer using the original packet structure if available to preserve protocol layers
            if original_packet and original_packet.haslayer(IP):
                # Use the original packet to maintain proper protocol structure
                ip_packet = copy.deepcopy(original_packet)
                
                # Apply target addressing if configured
                target = self.config.get_target('') 
                if target:
                    ip_packet[IP].dst = target
                
            else:
                # Fallback: parse the raw bytes as an IP packet
                ip_packet = IP(raw_bytes)
            
            # Use iteration for unique IP identification to avoid appearing as retransmissions
            if hasattr(ip_packet, 'id'):
                ip_packet.id = (ip_packet.id + iteration) % 65536
            
            # Handle TCP sequence number progression for connection tracking
            if ip_packet.haslayer('TCP'):
                tcp_layer = ip_packet['TCP']
                # Increment sequence number based on iteration and payload size
                payload_size = len(bytes(ip_packet.payload.payload)) if hasattr(ip_packet.payload, 'payload') else 0
                seq_increment = iteration * max(payload_size, 1)
                tcp_layer.seq = (tcp_layer.seq + seq_increment) % (2**32)
            
                seq_increment = iteration * max(payload_size, 1)
                tcp_layer.seq = (tcp_layer.seq + seq_increment) % (2**32)
            
            # Wrap with Ethernet for PCAP compatibility
            completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / ip_packet
            return bytes(completed)
            
        except (AttributeError, TypeError, ValueError):
            # Final fallback to raw bytes if packet parsing fails
            completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / Raw(load=raw_bytes)
            return bytes(completed)

    def close(self) -> None:
        """Close the raw IP socket."""
        super().close()
