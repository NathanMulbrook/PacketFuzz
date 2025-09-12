#!/usr/bin/env python3
"""
Telnet Client Socket Implementation

Wraps Python's telnetlib to provide Telnet client functionality for fuzzing data
transferred over Telnet connections.
"""
from __future__ import annotations

import telnetlib
import socket
import io
import logging
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class TelnetClientConfig(BaseSocketConfig):
    """Configuration for Telnet client socket."""
    host: str = '127.0.0.1'
    port: int = 23
    username: Optional[str] = None
    password: Optional[str] = None
    timeout: Optional[float] = 30.0
    one_connection_per_command: bool = False


class TelnetClientSocket(FuzzSocket):
    """
    Telnet client socket implementation for fuzzing data sent over Telnet.
    
    Features:
    - Uses telnetlib for Telnet protocol handling
    - Can fuzz command data sent to Telnet servers
    - Optional reconnection for each command
    
    Use case: Fuzzing data sent to Telnet servers, command fuzzing
    """

    def __init__(self, campaign) -> None:
        if not TELNETLIB_AVAILABLE:
            raise ImportError(
                "telnetlib is required for TelnetClientSocket but was not found. "
                "telnetlib was deprecated in Python 3.11 and removed in Python 3.13. "
                "Consider using a different socket type or install a telnet library."
            )
        
        super().__init__(campaign)
        cfg = self.socket_config
        self.socket_cfg: TelnetClientConfig = cfg if isinstance(cfg, TelnetClientConfig) else TelnetClientConfig()
        self._telnet_client: Optional[telnetlib.Telnet] = None
        self._connected = False
        self._last_response = None
        self.debug_mode = False  # Default value since TelnetClientConfig may not have debug_mode

    def open(self) -> "TelnetClientSocket":
        """Connect to Telnet server."""
        try:
            # Create Telnet client
            self._telnet_client = telnetlib.Telnet()
            
            # Connect to server
            self.logger.info(f"Connecting to {self.socket_cfg.host}:{self.socket_cfg.port}")
            self._telnet_client.open(
                self.socket_cfg.host,
                self.socket_cfg.port,
                self.socket_cfg.timeout
            )
            
            # Handle authentication if credentials provided
            if self.socket_cfg.username:
                # Wait for username prompt and send username
                self._telnet_client.read_until(b"login: ", self.socket_cfg.timeout)
                self._telnet_client.write(self.socket_cfg.username.encode() + b"\n")
                
                # Wait for password prompt and send password if provided
                if self.socket_cfg.password:
                    self._telnet_client.read_until(b"Password: ", self.socket_cfg.timeout)
                    self._telnet_client.write(self.socket_cfg.password.encode() + b"\n")
            
            self._connected = True
            self.logger.info("Connected to Telnet server")
            
            # Store the raw socket for compatibility
            self._sock = self._telnet_client.get_socket()
            
            return self
        except Exception as e:
            self.logger.error(f"Failed to connect to Telnet server: {e}")
            self.close()
            raise

    def send_packet(self, packet_bytes: bytes, context: 'CampaignContext') -> Optional[int]:
        """Send data over the Telnet connection."""
        if not self._connected or not self._telnet_client:
            if self.socket_cfg.one_connection_per_command:
                self.logger.info("Reconnecting for new command")
                self.open()
            else:
                raise RuntimeError("Not connected to Telnet server")
        
        # Send data
        if self.debug_mode:
            self.logger.debug(f"Sending {len(packet_bytes)} bytes: {packet_bytes}")
        
        if self._telnet_client is not None:
            self._telnet_client.write(packet_bytes)
        
        if self.socket_cfg.one_connection_per_command:
            # Read response before closing if configured for one command per connection
            if self._telnet_client is not None:
                self._last_response = self._telnet_client.read_all()
            self.close()
        
        return len(packet_bytes)

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Read response from the Telnet server."""
        if self._last_response:
            # Return cached response if available (from one_connection_per_command mode)
            response = self._last_response
            self._last_response = None
            return response
        
        if not self._connected or not self._telnet_client:
            self.logger.error("Not connected to Telnet server")
            return None
        
        try:
            # Use provided timeout or default from config
            actual_timeout = timeout if timeout is not None else self.socket_cfg.timeout
            
            # Read data until the server is idle
            # This is a simple implementation - might need refinement based on specific use cases
            response = self._telnet_client.read_eager()
            
            if self.debug_mode and response:
                self.logger.debug(f"Received {len(response)} bytes: {response}")
            
            return response
        except (ConnectionError, OSError, socket.error, EOFError) as e:
            self.logger.error(f"Network error receiving data: {e}")
            self._connected = False
            return None

    def close(self) -> None:
        """Close the Telnet connection."""
        if self._telnet_client:
            try:
                self._telnet_client.close()
            except (OSError, socket.error) as e:
                self.logger.error(f"Error closing Telnet connection: {e}")
            finally:
                self._telnet_client = None
                self._connected = False
                self._sock = None
                self._last_response = None

    def get_socket_info(self) -> dict:
        """Get socket information for reporting."""
        base_info = super().get_socket_info()
        base_info.update({
            "host": self.socket_cfg.host,
            "port": self.socket_cfg.port,
            "connected": self._connected,
            "one_connection_per_command": self.socket_cfg.one_connection_per_command
        })
        return base_info

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare Telnet client data for PCAP logging by wrapping in complete network stack.
        Telnet operates over TCP, so we create a TCP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP
        
        # Create TCP packet for Telnet communication (typically port 23)
        tcp_packet = TCP(
            sport=0,  # Client uses ephemeral port
            dport=self.socket_cfg.port,
            flags="PA"  # Push+Ack flags for data
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src="127.0.0.1",  # Local client
            dst=self.socket_cfg.host
        ) / tcp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)
