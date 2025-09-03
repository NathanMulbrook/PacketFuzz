#!/usr/bin/env python3
"""
Listening TCP Socket Implementation

Creates a TCP server socket that listens for incoming connections.
Useful for server-side fuzzing scenarios.
"""
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING

from .socket_interface import FuzzSocket

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


class ListeningTCPSocket(FuzzSocket):
    """
    Listening TCP socket implementation for server-mode fuzzing.
    
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

    def open(self) -> "ListeningTCPSocket":
        """Create and bind TCP listening socket."""
        try:
            # Create TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow socket reuse
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Get bind address and port from campaign
            bind_address = getattr(self.campaign, 'bind_address', '0.0.0.0')
            port = getattr(self.campaign, 'port', 8080)
            
            # Bind to address
            s.bind((bind_address, port))
            
            self._sock = s
            return self
        except Exception as e:
            raise OSError(f"Failed to create/bind TCP listening socket: {e}")



    def start_listening(self, backlog: int = 5) -> None:
        """Start listening for incoming connections."""
        if not self._sock:
            raise RuntimeError("Socket not open")
        
        try:
            self._sock.listen(backlog)
            self._listening = True
            bind_address = getattr(self.campaign, 'bind_address', '0.0.0.0')
            port = getattr(self.campaign, 'port', 8080)
            logging.getLogger(__name__).info(f"[ListeningTCPSocket] Listening on {bind_address}:{port}")
        except Exception as e:
            raise OSError(f"Failed to start listening: {e}")

    def accept_connection(self, timeout: Optional[float] = None) -> Optional[tuple['FuzzSocket', tuple[str, int]]]:
        """Accept an incoming TCP connection."""
        if not self._sock or not self._listening:
            return None
        
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            
            client_sock, client_addr = self._sock.accept()
            
            # Create a new FuzzSocket for the client connection
            client_socket = ClientTCPSocket(self.campaign, client_sock)
            return client_socket, client_addr
            
        except socket.timeout:
            logging.getLogger(__name__).debug("[ListeningTCPSocket] accept timeout")
            return None
        except Exception as e:
            logging.getLogger(__name__).error(f"[ListeningTCPSocket] accept failed: {e}")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)  # Reset to blocking

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """Listening sockets don't send directly - use accepted client connections."""
        logging.getLogger(__name__).warning("[ListeningTCPSocket] Cannot send on listening socket - use accepted client connection")
        return None

    

    def close(self) -> None:
        """Close the listening socket."""
        try:
            self._listening = False
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[ListeningTCPSocket] close error: {e}")


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
            return None
        
        try:
            return self._sock.send(packet_bytes)
        except Exception as e:
            logging.getLogger(__name__).error(f"[ClientTCPSocket] send failed: {e}")
            return None



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
        except Exception as e:
            logging.getLogger(__name__).error(f"[ClientTCPSocket] receive failed: {e}")
            return None
        finally:
            if timeout is not None:
                self._sock.settimeout(None)

    def close(self) -> None:
        """Close the client connection."""
        try:
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[ClientTCPSocket] close error: {e}")
