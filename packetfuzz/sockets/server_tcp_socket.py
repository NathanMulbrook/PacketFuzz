#!/usr/bin/env python3
"""
TCP Server Socket Implementation

Creates a TCP server socket that listens for incoming connections.
Useful for server-side fuzzing scenarios.
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
class ServerTCPConfig(BaseSocketConfig):
    """Configuration for a TCP server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 8080


class ServerTCPSocket(FuzzSocket):
    """
    TCP server socket implementation for server-mode fuzzing.
    
    Features:
    - Binds to specified port
    - Listens for incoming TCP connections
    - Can accept multiple clients
    - No root privileges required
    
    Use case: Server-side protocol fuzzing, testing client implementations
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        self._listening = False
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg = cfg if isinstance(cfg, ServerTCPConfig) else ServerTCPConfig()

    def open(self) -> "ServerTCPSocket":
        """Create and bind TCP listening socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow socket reuse
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            bind_address = self.socket_cfg.bind_address
            port = self.socket_cfg.port
            
            s.bind((bind_address, port))
            
            self._sock = s
            return self
        except (OSError, socket.error) as e:
            raise OSError(f"Failed to create/bind TCP listening socket: {e}")



    def start_listening(self, backlog: int = 5) -> None:
        """Start listening for incoming connections."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        try:
            self._sock.listen(backlog)
            self._listening = True
            logging.getLogger(__name__).info(f"[ServerTCPSocket] Listening on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
        except (OSError, socket.error) as e:
            raise OSError(f"Failed to start listening: {e}")

    def accept_connection(self, timeout: Optional[float] = None) -> Optional[tuple['FuzzSocket', tuple[str, int]]]:
        """Accept an incoming TCP connection."""
        if not self._sock or not self._listening:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            client_sock, client_addr = self._sock.accept()
            
            client_socket = ClientTCPSocket(self.campaign, client_sock)
            return client_socket, client_addr
            
        except socket.timeout:
            return None
        except (ConnectionError, OSError, socket.error) as e:
            logging.getLogger(__name__).error(f"[ServerTCPSocket] network error during accept: {e}")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Listening sockets don't send directly - use accepted client connections."""
        logging.getLogger(__name__).warning("[ServerTCPSocket] Cannot send on listening socket - use accepted client connection")
        return None

    

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare TCP server data for PCAP logging by wrapping in complete network stack.
        For server sockets, we create a complete TCP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP
        
        tcp_packet = TCP(
            sport=self.socket_config.port,
            dport=0,  # Unknown client port for server
            flags="A"  # ACK flag for server response
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src=self.socket_config.host,
            dst="0.0.0.0"  # Unknown destination for server
        ) / tcp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)

    def close(self) -> None:
        """Close the listening socket."""
        self._listening = False
        super().close()


class ClientTCPSocket(FuzzSocket):
    """
    Client TCP socket wrapper for accepted connections.
    """

    def __init__(self, campaign, client_sock: socket.socket) -> None:
        super().__init__(campaign)
        self._sock = client_sock

    def open(self) -> "ClientTCPSocket":
        """Already connected - no-op."""
        return self

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Send data to the connected client."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        return self._sock.send(packet_bytes)



    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive data from the connected client."""
        if not self._sock:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            data = self._sock.recv(4096)
            return data if data else None
        except socket.timeout:
            logging.getLogger(__name__).debug("[ClientTCPSocket] receive timeout")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare packet for PCAP logging with full TCP/IP/Ethernet stack for client connection.
        
        For server-side TCP client connections, we create a complete protocol stack
        with the raw fuzzed bytes as the TCP payload.
        """
        from scapy.layers.l2 import Ether, Raw
        from scapy.layers.inet import IP, TCP
        from scapy.volatile import RandInt, RandShort
        import random
        
        # For server-side connections, we reverse src/dst
        sport = random.randint(49152, 65535)
        
        completed = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / \
                   IP(dst="127.0.0.1", src="127.0.0.1") / \
                   TCP(dport=sport, sport=80) / Raw(load=raw_bytes)
        
        # Populate connection fields for clean PCAP output
        try:
            completed[TCP].seq = RandInt()
            del completed[TCP].chksum  # Let Scapy recalculate
            completed[IP].id = RandShort()
            del completed[IP].chksum  # Let Scapy recalculate
        except Exception as e:
            logging.getLogger(__name__).debug(f"Could not populate connection fields: {e}")
        
        return bytes(completed)

    def close(self) -> None:
        """Close the client connection."""
        try:
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
            super().close()
        except (ConnectionError, OSError, socket.error) as e:
            logging.getLogger(__name__).warning(f"[ClientTCPSocket] close error: {e}")
