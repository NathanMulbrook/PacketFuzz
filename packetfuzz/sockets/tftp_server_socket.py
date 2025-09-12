#!/usr/bin/env python3
"""
TFTP Server Socket Implementation

Wraps tftpy to provide TFTP server functionality for fuzzing data
received from TFTP clients. TFTP is a simple UDP-based file transfer protocol.
"""
from __future__ import annotations

import tftpy
import socket
import threading
import tempfile
import os
import io
from typing import Optional, TYPE_CHECKING, Any
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class TFTPServerConfig(BaseSocketConfig):
    """Configuration for TFTP server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 69
    root_directory: Optional[str] = None  # If None, creates temp directory
    timeout: Optional[float] = 5.0
    retries: int = 5
    enable_upload: bool = True
    enable_download: bool = True


class TFTPServerSocket(FuzzSocket):
    """
    TFTP server socket implementation for fuzzing data received from TFTP clients.
    
    Features:
    - Uses tftpy for full TFTP server functionality
    - Captures uploaded data for fuzzing analysis
    - Can serve fuzzed data for download operations
    - Simple UDP-based protocol
    - Configurable upload/download permissions
    
    Use case: Server-side TFTP fuzzing, analyzing client uploads
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: TFTPServerConfig = cfg if isinstance(cfg, TFTPServerConfig) else TFTPServerConfig()
        
        self._server: Optional[tftpy.TftpServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._temp_dir: Optional[str] = None
        self._running = False
        
        # Data for fuzzing
        self._fuzzed_download_data: Optional[bytes] = None
        self._captured_uploads: list[tuple[bytes, str]] = []  # (data, filename)

    def open(self) -> "TFTPServerSocket":
        """Create and configure TFTP server."""
 
        # Set up root directory
        if self.socket_cfg.root_directory:
            root_dir = self.socket_cfg.root_directory
        else:
            self._temp_dir = tempfile.mkdtemp(prefix='tftp_server_')
            root_dir = self._temp_dir
        
        # Create TFTP server
        self._server = tftpy.TftpServer(root_dir)
        
        # Note: tftpy server configuration is handled via listen() method parameters
        # Individual timeout/retry settings are managed per-session
        
        self.logger.info(f"TFTP server configured on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
        self.logger.info(f"Root directory: {root_dir}")
        return self

    def start_listening(self, backlog: int = 5) -> None:
        """Start the TFTP server in a background thread."""
        if not self._server:
            raise RuntimeError("TFTP server not configured")
        
        if self._running:
            self.logger.warning("TFTP server already running")
            return
        
        def server_loop():
            try:
                self.logger.info("Starting TFTP server...")
                if self._server:
                    # Convert timeout to int if specified
                    timeout_int = int(self.socket_cfg.timeout) if self.socket_cfg.timeout else 5
                    self._server.listen(
                        self.socket_cfg.bind_address,
                        self.socket_cfg.port,
                        timeout=timeout_int
                    )
            except (OSError, socket.error, ValueError) as e:
                self.logger.error("TFTP server error", e)
        
        self._server_thread = threading.Thread(target=server_loop, daemon=True)
        self._server_thread.start()
        self._running = True
        
        self.logger.info(f"TFTP server listening on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")

    @property
    def is_open(self) -> bool:
        """Check if TFTP server is configured."""
        return self._server is not None

    @property
    def raw(self) -> Optional[tftpy.TftpServer]:
        """Return underlying TFTP server for compatibility."""
        return self._server

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """
        Set fuzzed data to be served for download operations.
        
        The packet_bytes will be served when clients download files.
        Creates a file in the server root with the fuzzed data.
        """
        if not self.is_open or not self._temp_dir:
            raise RuntimeError("TFTP server not configured")
        
        # Get filename from context or use default
        filename = getattr(context, 'tftp_filename', 'fuzzed_file.bin')
        
        # Write fuzzed data to server root directory
        root_dir = self._temp_dir or self.socket_cfg.root_directory
        if root_dir:
            file_path = os.path.join(root_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(packet_bytes)
            
            self._fuzzed_download_data = packet_bytes
            self.logger.debug(f"Set {len(packet_bytes)} bytes of fuzzed data for downloads as {filename}")
            return len(packet_bytes)
        
        return None

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Get data captured from client uploads.
        
        Returns the most recently uploaded data from TFTP clients.
        Note: This requires monitoring the server directory for new files.
        """
        if self._captured_uploads:
            data, filename = self._captured_uploads[-1]
            self.logger.debug(f"Retrieved {len(data)} bytes from upload: {filename}")
            return data
        
        # Try to scan for new uploads in the directory
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                for filename in os.listdir(self._temp_dir):
                    file_path = os.path.join(self._temp_dir, filename)
                    if os.path.isfile(file_path):
                        # Check if this is a new upload
                        if not any(fn == filename for _, fn in self._captured_uploads):
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            self._captured_uploads.append((data, filename))
                            self.logger.debug(f"Captured new upload: {filename} ({len(data)} bytes)")
                            return data
            except OSError as e:
                # Scanning failure indicates an IO issue - log at error level and re-raise
                self.logger.error(f"Error scanning for uploads: {e}")
                raise
        
        return None

    def get_captured_uploads(self) -> list[tuple[bytes, str]]:
        """Get all captured upload data with filenames."""
        return self._captured_uploads.copy()

    def clear_captured_data(self) -> None:
        """Clear captured upload data."""
        self._captured_uploads.clear()

    def monitor_uploads(self) -> None:
        """
        Monitor the server directory for new uploads.
        This should be called periodically to capture uploaded files.
        """
        self.receive_response()  # This will scan for new files

    def close(self) -> None:
        """Stop TFTP server and clean up."""
        self._running = False
        
        if self._server:
            try:
                self._server.stop()
            except Exception as e:
                # Stopping the server failing is a runtime error - log and re-raise
                self.logger.error(f"Error stopping TFTP server: {e}")
                raise
        
        if self._server_thread and self._server_thread.is_alive():
            # Give server time to shutdown gracefully
            self._server_thread.join(timeout=2.0)
        
        # Clean up temp directory
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                import shutil
                shutil.rmtree(self._temp_dir)
            except Exception as e:
                # Cleanup failures should be visible
                self.logger.error(f"Failed to clean up temp directory: {e}")
                raise
        
        self._server = None
        self._server_thread = None
        super().close()

    def get_socket_info(self) -> dict:
        """Get TFTP server information."""
        base_info = super().get_socket_info()
        base_info.update({
            "bind_address": self.socket_cfg.bind_address,
            "port": self.socket_cfg.port,
            "root_directory": self.socket_cfg.root_directory or self._temp_dir,
            "timeout": self.socket_cfg.timeout,
            "retries": self.socket_cfg.retries,
            "enable_upload": self.socket_cfg.enable_upload,
            "enable_download": self.socket_cfg.enable_download,
            "running": self._running,
            "captured_uploads": len(self._captured_uploads)
        })
        return base_info

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare TFTP server data for PCAP logging by wrapping in complete network stack.
        TFTP operates over UDP, so we create a UDP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        
        # Create UDP packet for TFTP server response (typically port 69)
        udp_packet = UDP(
            sport=self.socket_cfg.port,
            dport=0  # Unknown client port for server
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src=self.socket_cfg.bind_address,
            dst="0.0.0.0"  # Unknown destination for server
        ) / udp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)
