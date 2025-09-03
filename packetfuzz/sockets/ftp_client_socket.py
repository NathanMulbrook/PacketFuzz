#!/usr/bin/env python3
"""
FTP Client Socket Implementation

Wraps Python's ftplib to provide FTP client functionality for fuzzing data
transferred over FTP connections. Supports both active and passive modes.
"""
from __future__ import annotations

import ftplib
import io
import logging
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class FTPClientConfig(BaseSocketConfig):
    """Configuration for FTP client socket."""
    host: str = '127.0.0.1'
    port: int = 21
    username: str = 'anonymous'
    password: str = 'anonymous@'
    passive_mode: bool = True
    timeout: Optional[float] = 30.0
    one_connection_per_file: bool = False


class FTPClientSocket(FuzzSocket):
    """
    FTP client socket implementation for fuzzing data sent over FTP.
    
    Features:
    - Uses ftplib for FTP protocol handling
    - Supports active and passive modes
    - Can fuzz file upload (STOR) and download (RETR) operations
    - Optional reconnection for each file transfer
    
    Use case: Fuzzing data sent to FTP servers, file content fuzzing
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: FTPClientConfig = cfg if isinstance(cfg, FTPClientConfig) else FTPClientConfig()
        self._ftp_client: Optional[ftplib.FTP] = None
        self._connected = False

    def open(self) -> "FTPClientSocket":
        """Connect to FTP server and authenticate."""
        try:
            # Create FTP client
            self._ftp_client = ftplib.FTP()
            
            if self.socket_cfg.timeout:
                self._ftp_client.timeout = self.socket_cfg.timeout
            
            # Connect to server
            self._ftp_client.connect(self.socket_cfg.host, self.socket_cfg.port)
            
            # Login
            self._ftp_client.login(self.socket_cfg.username, self.socket_cfg.password)
            
            # Set transfer mode
            self._ftp_client.set_pasv(self.socket_cfg.passive_mode)
            
            self._connected = True
            self.logger.info(f"Connected to FTP server {self.socket_cfg.host}:{self.socket_cfg.port}")
            return self
        except Exception as e:
            error_msg = f"Failed to connect to FTP server {self.socket_cfg.host}:{self.socket_cfg.port}"
            self.logger.error(error_msg, e)
            raise OSError(f"{error_msg}: {e}")

    @property
    def is_open(self) -> bool:
        """Check if FTP connection is open."""
        return self._connected and self._ftp_client is not None

    @property
    def raw(self) -> Optional[ftplib.FTP]:
        """Return underlying FTP client for compatibility."""
        return self._ftp_client

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """
        Send fuzzed data via FTP upload (STOR command).
        
        The packet_bytes will be sent as file content to the FTP server.
        Uses a default filename 'fuzzed_file.bin' unless specified in context.
        """
        if not self.is_open or not self._ftp_client:
            self.logger.error("FTP client not connected")
            return None
        
        try:
            # Handle reconnection if configured
            if self.socket_cfg.one_connection_per_file:
                self._reconnect()
            
            # Get filename from context or use default
            filename = getattr(context, 'ftp_filename', 'fuzzed_file.bin')
            
            # Create file-like object from fuzzed data
            data_stream = io.BytesIO(packet_bytes)
            
            # Upload fuzzed data
            self._ftp_client.storbinary(f'STOR {filename}', data_stream)
            
            self.logger.debug(f"Uploaded {len(packet_bytes)} bytes as {filename}")
            return len(packet_bytes)
            
        except Exception as e:
            self.logger.error("FTP upload failed", e)
            return None

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Download file from FTP server (RETR command).
        
        Can be used to fuzz download operations or verify server responses.
        Downloads from filename specified in context or 'test_file.bin'.
        """
        if not self.is_open or not self._ftp_client:
            return None
        
        try:
            # Get filename from context or use default
            filename = getattr(self, '_download_filename', 'test_file.bin')
            
            # Buffer to collect downloaded data
            data_buffer = io.BytesIO()
            
            # Download file
            self._ftp_client.retrbinary(f'RETR {filename}', data_buffer.write)
            
            downloaded_data = data_buffer.getvalue()
            self.logger.debug(f"Downloaded {len(downloaded_data)} bytes from {filename}")
            return downloaded_data
            
        except Exception as e:
            self.logger.error("FTP download failed", e)
            return None

    def set_download_filename(self, filename: str) -> None:
        """Set filename for download operations."""
        self._download_filename = filename

    def _reconnect(self) -> None:
        """Reconnect to FTP server (used with one_connection_per_file)."""
        try:
            if self._ftp_client:
                self._ftp_client.quit()
        except:
            pass  # Ignore errors during disconnect
        
        # Reopen connection
        self.open()

    def close(self) -> None:
        """Close FTP connection."""
        if self._ftp_client:
            try:
                self._ftp_client.quit()
            except:
                pass  # Ignore errors during close
        
        self._ftp_client = None
        self._connected = False
        super().close()

    def get_socket_info(self) -> dict:
        """Get FTP client information."""
        base_info = super().get_socket_info()
        base_info.update({
            "host": self.socket_cfg.host,
            "port": self.socket_cfg.port,
            "username": self.socket_cfg.username,
            "passive_mode": self.socket_cfg.passive_mode,
            "one_connection_per_file": self.socket_cfg.one_connection_per_file,
            "connected": self._connected
        })
        return base_info
