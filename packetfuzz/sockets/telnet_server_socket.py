#!/usr/bin/env python3
"""
Telnet Server Socket Implementation

Provides a simple Telnet server implementation for fuzzing data
received from Telnet clients.
"""
from __future__ import annotations

import socket
import threading
import logging
import select
import io
import os
from typing import Optional, TYPE_CHECKING, Any, Dict, List, Tuple
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class TelnetServerConfig(BaseSocketConfig):
    """Configuration for Telnet server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 23
    max_connections: int = 5
    timeout: Optional[float] = 60.0
    banner: str = "Welcome to PacketFuzz Telnet Server\r\n"
    prompt: str = "$ "


class TelnetConnection:
    """Represents a single Telnet client connection."""
    
    def __init__(self, sock: socket.socket, address: Tuple[str, int], server: 'TelnetServerSocket'):
        self.sock = sock
        self.address = address
        self.server = server
        self.buffer = b""
        self.closed = False
        self.socket_file = sock.makefile('rwb')
        self.last_activity = threading.Event()
        self.last_activity.set()
    
    def send(self, data: bytes) -> int:
        """Send data to the client."""
        try:
            return self.sock.send(data)
        except (ConnectionError, OSError, socket.error) as e:
            self.server.logger.error(f"Network error sending to {self.address}: {e}")
            self.closed = True
            return 0
    
    def recv(self, size: int = 1024) -> bytes:
        """Receive data from the client."""
        try:
            data = self.sock.recv(size)
            if not data:
                self.closed = True
            self.last_activity.set()
            return data
        except (ConnectionError, OSError, socket.error) as e:
            self.server.logger.error(f"Network error receiving from {self.address}: {e}")
            self.closed = True
            return b""
    
    def close(self) -> None:
        """Close the connection."""
        try:
            self.socket_file.close()
            self.sock.close()
        except (OSError, socket.error) as e:
            # Log close errors - these are usually benign but should be visible
            self.server.logger.warning(f"Error closing connection socket/file: {e}")
        finally:
            self.closed = True


class TelnetServerSocket(FuzzSocket):
    """
    Telnet server socket implementation for fuzzing data received from Telnet clients.
    
    Features:
    - Simple Telnet server implementation
    - Handles multiple concurrent connections
    - Captures client commands for fuzzing
    
    Use case: Fuzzing data received from Telnet clients, server-side fuzzing
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: TelnetServerConfig = cfg if isinstance(cfg, TelnetServerConfig) else TelnetServerConfig()
        self._server_sock: Optional[socket.socket] = None
        self._connections: List[TelnetConnection] = []
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._received_data = io.BytesIO()
        self._lock = threading.Lock()
        self.debug_mode = getattr(self.campaign, 'debug_mode', False)

    def open(self) -> "TelnetServerSocket":
        """Create and configure the Telnet server socket."""
        try:
            # Create server socket
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to the specified address and port
            self.logger.info(f"Binding to {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
            self._server_sock.bind((self.socket_cfg.bind_address, self.socket_cfg.port))
            
            # Store the server socket for compatibility
            self._sock = self._server_sock
            
            return self
        except Exception as e:
            self.logger.error(f"Failed to create Telnet server: {e}")
            self.close()
            raise

    def start_listening(self, backlog: int = 5) -> None:
        """Start listening for incoming connections."""
        if not self._server_sock:
            raise RuntimeError("Server socket not initialized. Call open() first.")
        
        try:
            # Start listening with the specified or default backlog
            actual_backlog = min(backlog, self.socket_cfg.max_connections)
            self._server_sock.listen(actual_backlog)
            self.logger.info(f"Listening for Telnet connections on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
            
            # Start the server thread
            self._running = True
            self._server_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._server_thread.start()
        except Exception as e:
            self.logger.error(f"Failed to start listening: {e}")
            self._running = False
            raise

    def _accept_loop(self) -> None:
        """Thread function to accept incoming connections."""
        try:
            while self._running and self._server_sock:
                try:
                    # Use select to avoid blocking indefinitely
                    readable, _, _ = select.select([self._server_sock], [], [], 1.0)
                    
                    if self._server_sock in readable:
                        client_sock, client_addr = self._server_sock.accept()
                        self._handle_new_connection(client_sock, client_addr)
                except (ConnectionError, OSError, socket.error) as e:
                    if self._running:
                        self.logger.error(f"Network error in accept loop: {e}")
        except Exception as e:
            self.logger.error(f"Accept loop terminated: {e}")
        finally:
            self._running = False

    def _handle_new_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Handle a new client connection."""
        try:
            self.logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
            
            # Set socket options
            client_sock.setblocking(True)
            if self.socket_cfg.timeout:
                client_sock.settimeout(self.socket_cfg.timeout)
            
            # Create a connection object
            connection = TelnetConnection(client_sock, client_addr, self)
            
            # Send welcome banner
            if self.socket_cfg.banner:
                connection.send(self.socket_cfg.banner.encode())
            
            # Send prompt
            if self.socket_cfg.prompt:
                connection.send(self.socket_cfg.prompt.encode())
            
            # Add to active connections
            with self._lock:
                self._connections.append(connection)
            
            # Start a thread to handle this client
            client_thread = threading.Thread(
                target=self._handle_client,
                args=(connection,),
                daemon=True
            )
            client_thread.start()
        except (ConnectionError, OSError, socket.error) as e:
            self.logger.error(f"Network error handling new connection: {e}")
            try:
                client_sock.close()
            except (OSError, socket.error) as close_e:
                self.logger.error(f"Error closing client socket after failed handle: {close_e}")

    def _handle_client(self, connection: TelnetConnection) -> None:
        """Handle communication with a connected client."""
        try:
            buffer = b""
            while not connection.closed and self._running:
                try:
                    # Read data from client
                    data = connection.recv(1024)
                    if not data:
                        break
                    
                    if self.debug_mode:
                        self.logger.debug(f"Received from {connection.address}: {data}")
                    
                    # Process telnet commands and escape sequences
                    # This is a simplified implementation - a production server would handle
                    # proper telnet protocol negotiation
                    buffer += data
                    
                    # Check for line ending (CR+LF or just CR in telnet)
                    if b'\r\n' in buffer or b'\r' in buffer:
                        # Split on CR+LF or CR
                        lines = buffer.replace(b'\r\n', b'\n').replace(b'\r', b'\n').split(b'\n')
                        
                        # Keep the last incomplete line in buffer
                        buffer = lines.pop() if not buffer.endswith(b'\n') else b""
                        
                        # Process complete lines
                        for line in lines:
                            if line:
                                self._process_command(connection, line)
                                
                                # Store received data for fuzzing
                                with self._lock:
                                    self._received_data.write(line + b"\n")
                                
                                # Echo the prompt after each command
                                if self.socket_cfg.prompt:
                                    connection.send(self.socket_cfg.prompt.encode())
                except socket.timeout:
                    # Handle timeout - could implement idle disconnect here
                    continue
                except (ConnectionError, OSError, socket.error) as e:
                    if not connection.closed:
                        self.logger.error(f"Network error handling client {connection.address}: {e}")
                    break
        finally:
            # Clean up the connection
            connection.close()
            with self._lock:
                if connection in self._connections:
                    self._connections.remove(connection)
            self.logger.info(f"Connection closed: {connection.address}")

    def _process_command(self, connection: TelnetConnection, command: bytes) -> None:
        """Process a command received from the client."""
        try:
            # This is where you would handle the command and send a response
            # For the fuzzer, we'll just echo the command back to simulate a response
            
            # Decode the command to string (with fallbacks)
            try:
                cmd_str = command.decode('utf-8')
            except UnicodeDecodeError:
                cmd_str = command.decode('latin1', errors='replace')
            
            self.logger.info(f"Command from {connection.address}: {cmd_str}")
            
            # Simple echo response
            response = f"Received: {cmd_str}\r\n"
            connection.send(response.encode())
            
        except (ConnectionError, OSError, socket.error, UnicodeDecodeError) as e:
            self.logger.error(f"Error processing command: {e}")

    def send_packet(self, packet_bytes: bytes, context: 'CampaignContext') -> Optional[int]:
        """
        Send packet to all connected clients.
        
        For a Telnet server, this would typically be a response to a command
        or server-initiated message.
        """
        if not self._running:
            self.logger.error("Server not running")
            return None
        
        # Make a copy of the connections list to avoid issues with concurrent modification
        with self._lock:
            connections = self._connections.copy()
        
        if not connections:
            self.logger.warning("No connected clients to send data to")
            return 0
        
        total_sent = 0
        for connection in connections:
            try:
                if not connection.closed:
                    bytes_sent = connection.send(packet_bytes)
                    total_sent += bytes_sent
                    
                    if self.debug_mode:
                        self.logger.debug(f"Sent {bytes_sent} bytes to {connection.address}")
            except (ConnectionError, OSError, socket.error) as e:
                self.logger.error(f"Failed to send to {connection.address}: {e}")
        
        return total_sent if total_sent > 0 else None

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Get the accumulated received data from clients.
        
        For the Telnet server, this returns all the commands received from clients
        since the last call to this method.
        """
        with self._lock:
            # Get current position
            pos = self._received_data.tell()
            
            # Reset to beginning to read all data
            self._received_data.seek(0)
            
            # Read accumulated data
            data = self._received_data.read()
            
            # Clear the buffer and reset position
            self._received_data = io.BytesIO()
            
            return data if data else None

    def accept_connection(self, timeout: Optional[float] = None) -> Optional[Tuple[FuzzSocket, Tuple[str, int]]]:
        """
        Accept a new connection directly.
        
        Note: This is generally not needed when using start_listening() which
        handles connections in a background thread.
        """
        if not self._server_sock:
            self.logger.error("Server socket not initialized")
            return None
        
        try:
            # Set a timeout for the accept call if specified
            if timeout is not None:
                self._server_sock.settimeout(timeout)
            
            # Accept the connection
            client_sock, client_addr = self._server_sock.accept()
            
            # Reset to blocking mode if needed
            if timeout is not None:
                self._server_sock.settimeout(None)
            
            # Create a connection object but don't start a handling thread
            connection = TelnetConnection(client_sock, client_addr, self)
            
            # Add to active connections
            with self._lock:
                self._connections.append(connection)
            
            # Return the client socket and address
            # Note: This doesn't follow the expected return type exactly as we
            # don't have a FuzzSocket per client, but it's close enough for compatibility
            return self, client_addr
        except socket.timeout:
            # Reset to blocking mode if needed
            if timeout is not None:
                self._server_sock.settimeout(None)
            return None
        except (ConnectionError, OSError, socket.error) as e:
            self.logger.error(f"Network error accepting connection: {e}")
            # Reset to blocking mode if needed
            if timeout is not None:
                try:
                    self._server_sock.settimeout(None)
                except (OSError, socket.error):
                    pass
            return None

    def close(self) -> None:
        """Close the server and all client connections."""
        # Stop the accept loop
        self._running = False
        
        # Close all client connections
        with self._lock:
            for connection in self._connections:
                try:
                    connection.close()
                except (OSError, socket.error):
                    pass
            self._connections.clear()
        
        # Close server socket
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception as e:
                # Closing server socket failed - log and re-raise to make caller aware
                self.logger.error(f"Error closing server socket: {e}")
                raise
            finally:
                self._server_sock = None
                self._sock = None
        
        # Wait for server thread to terminate
        if self._server_thread and self._server_thread.is_alive():
            try:
                self._server_thread.join(2.0)
            except RuntimeError as e:
                self.logger.error(f"Error joining server thread: {e}")
            finally:
                self._server_thread = None

    def get_socket_info(self) -> dict:
        """Get socket information for reporting."""
        base_info = super().get_socket_info()
        
        # Count active connections
        connection_count = 0
        with self._lock:
            connection_count = len(self._connections)
            
        base_info.update({
            "bind_address": self.socket_cfg.bind_address,
            "port": self.socket_cfg.port,
            "running": self._running,
            "active_connections": connection_count,
            "max_connections": self.socket_cfg.max_connections
        })
        return base_info

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare Telnet server data for PCAP logging by wrapping in complete network stack.
        Telnet operates over TCP, so we create a TCP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP
        
        # Create TCP packet for Telnet server response (typically port 23)
        tcp_packet = TCP(
            sport=self.socket_cfg.port,
            dport=0,  # Unknown client port for server
            flags="PA"  # Push+Ack flags for data
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src=self.socket_cfg.bind_address,
            dst="0.0.0.0"  # Unknown destination for server
        ) / tcp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)
