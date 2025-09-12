#!/usr/bin/env python3
"""
UDP Server Socket Implementation

Creates a UDP server socket that binds to a port and receives datagrams.
Useful for server-side UDP fuzzing scenarios.
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
class ServerUDPConfig(BaseSocketConfig):
    """Configuration for a UDP server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 5353


class ServerUDPSocket(FuzzSocket):
    """
    UDP server socket implementation for server-mode fuzzing.
    
    Features:
    - Binds to specified port
    - Receives UDP datagrams
    - Can respond to clients
    - No root privileges required
    
    Use case: Server-side UDP protocol fuzzing, testing client implementations
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        self._listening = False
        self._last_client_addr = None
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg = cfg if isinstance(cfg, ServerUDPConfig) else ServerUDPConfig()

    def open(self) -> "ServerUDPSocket":
        """Create and bind UDP listening socket."""
        try:
            # Create UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Allow socket reuse
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address
            s.bind((self.socket_cfg.bind_address, self.socket_cfg.port))
            
            self._sock = s
            return self
        except (OSError, socket.error) as e:
            raise OSError(f"Failed to create/bind UDP listening socket: {e}")



    def start_listening(self, backlog: int = 5) -> None:
        """Start listening for incoming datagrams."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        try:
            self._listening = True
            logging.getLogger(__name__).info(f"[ServerUDPSocket] Listening on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
        except (OSError, socket.error) as e:
            raise OSError(f"Failed to start listening: {e}")

    def accept_connection(self, timeout: Optional[float] = None) -> Optional[tuple['FuzzSocket', tuple[str, int]]]:
        """Wait for incoming UDP datagram (simulates 'accepting' a client)."""
        if not self._sock or not self._listening:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            # Receive a datagram to identify a client
            data, client_addr = self._sock.recvfrom(4096)
            self._last_client_addr = client_addr
            
            # Create a UDP client socket that can respond to this specific client
            client_socket = ClientUDPSocket(self.campaign, self._sock, client_addr, data)
            return client_socket, client_addr
            
        except socket.timeout:
            logging.getLogger(__name__).debug("[ServerUDPSocket] accept timeout")
            return None
        except (ConnectionError, OSError, socket.error) as e:
            logging.getLogger(__name__).error(f"[ServerUDPSocket] network error during accept: {e}")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send response to the last client that contacted us."""
        if not self._sock or not self._last_client_addr:
            raise RuntimeError("No client address available for response")
        
        return self._sock.sendto(packet_bytes, self._last_client_addr)



    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive a UDP datagram."""
        if not self._sock:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            data, addr = self._sock.recvfrom(4096)
            self._last_client_addr = addr  # Update last client
            return data if data else None
        except socket.timeout:
            logging.getLogger(__name__).debug("[ServerUDPSocket] receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare UDP server data for PCAP logging by wrapping in complete network stack.
        For server sockets, we create a complete UDP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        
        # Create UDP packet with server context
        udp_packet = UDP(
            sport=self.socket_config.port,
            dport=0  # Unknown client port for server
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src=self.socket_config.host,
            dst="0.0.0.0"  # Unknown destination for server
        ) / udp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)

    def close(self) -> None:
        """Close the listening socket."""
        self._listening = False
        super().close()


class ClientUDPSocket(FuzzSocket):
    """
    Client UDP socket wrapper for responding to specific UDP clients.
    """

    def __init__(self, campaign, server_sock: socket.socket, client_addr: tuple[str, int], initial_data: bytes) -> None:
        super().__init__(campaign)
        self._server_sock = server_sock  # Reference to the server socket
        self._client_addr = client_addr
        self._initial_data = initial_data
        self._sock = server_sock  # Use the same socket

    def open(self) -> "ClientUDPSocket":
        """Already connected - no-op."""
        return self

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send UDP datagram to the specific client."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        return self._sock.sendto(packet_bytes, self._client_addr)



    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive UDP datagram from the specific client."""
        if not self._sock:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            # Keep receiving until we get data from our specific client
            while True:
                data, addr = self._sock.recvfrom(4096)
                if addr == self._client_addr:
                    return data if data else None
                # Ignore data from other clients
                
        except socket.timeout:
            logging.getLogger(__name__).debug("[ClientUDPSocket] receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)

    def get_initial_data(self) -> bytes:
        """Get the initial data received from this client."""
        return self._initial_data

    def get_client_address(self) -> tuple[str, int]:
        """Get the address of this client."""
        return self._client_addr

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare UDP client data for PCAP logging by wrapping in complete network stack.
        For client sockets created by server, we create a complete UDP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        
        # Create UDP packet with client context (we know both endpoints)
        udp_packet = UDP(
            sport=self._client_addr[1],
            dport=self._server_sock.getsockname()[1]  # Server port
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src=self._client_addr[0],
            dst=self._server_sock.getsockname()[0]  # Server IP
        ) / udp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)

    def close(self) -> None:
        """Close connection to this client (no-op for UDP)."""
        # For UDP, we don't actually close the socket since it's shared with the server
        pass
