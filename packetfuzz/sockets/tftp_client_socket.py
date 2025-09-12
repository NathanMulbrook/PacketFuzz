#!/usr/bin/env python3
"""
TFTP Client Socket Implementation

Wraps tftpy to provide TFTP client functionality for fuzzing data
transferred over TFTP connections. TFTP is a simple UDP-based file transfer protocol.
"""
from __future__ import annotations

import tftpy
import tempfile
import os
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .base_socket import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class TFTPClientConfig(BaseSocketConfig):
    """Configuration for TFTP client socket."""
    host: str = '127.0.0.1'
    port: int = 69
    timeout: Optional[float] = 5.0
    retries: int = 5
    block_size: int = 512


class TFTPClientSocket(FuzzSocket):
    """
    TFTP client socket implementation for fuzzing data sent over TFTP.
    
    Features:
    - Uses tftpy for TFTP protocol handling
    - Supports uploading fuzzed data as files to TFTP servers
    - Can download files from TFTP servers for verification
    - Simple UDP-based protocol
    
    Use case: Fuzzing data sent to TFTP servers, file content fuzzing
    """

    def __init__(self, campaign) -> None:
        if not TFTPY_AVAILABLE:
            raise ImportError(
                "tftpy is required for TFTPClientSocket. "
                "Please install it using 'pip install tftpy'"
            )
        
        super().__init__(campaign)
        cfg = self.socket_config
        self.socket_cfg: TFTPClientConfig = cfg if isinstance(cfg, TFTPClientConfig) else TFTPClientConfig()
        self._tftp_client: Optional[tftpy.TftpClient] = None
        self._temp_dir: Optional[str] = None

    def open(self) -> "TFTPClientSocket":
        """Create TFTP client and set up temporary directory."""
        try:
            self._tftp_client = tftpy.TftpClient(
                self.socket_cfg.host,
                self.socket_cfg.port,
                options={
                    'timeout': self.socket_cfg.timeout,
                    'retries': self.socket_cfg.retries,
                    'blksize': self.socket_cfg.block_size
                }
            )
            
            self._temp_dir = tempfile.mkdtemp(prefix='tftp_client_')
            
            self.logger.info(f"TFTP client configured for {self.socket_cfg.host}:{self.socket_cfg.port}")
            return self
        except (OSError, IOError) as e:
            error_msg = f"Failed to create TFTP client for {self.socket_cfg.host}:{self.socket_cfg.port}"
            self.logger.error(error_msg, e)
            raise OSError(f"{error_msg}: {e}")

    @property
    def is_open(self) -> bool:
        """Check if TFTP client is configured."""
        return self._tftp_client is not None

    @property
    def raw(self) -> Optional[tftpy.TftpClient]:
        """Return underlying TFTP client for compatibility."""
        return self._tftp_client

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """
        Send fuzzed data via TFTP upload.
        
        The packet_bytes will be sent as file content to the TFTP server.
        Uses a default filename 'fuzzed_file.bin' unless specified in context.
        """
        if not self.is_open or not self._tftp_client or not self._temp_dir:
            raise RuntimeError("TFTP client not configured")
        
        filename = getattr(context, 'tftp_filename', 'fuzzed_file.bin')
        
        temp_file_path = os.path.join(self._temp_dir, 'upload_data')
        with open(temp_file_path, 'wb') as f:
            f.write(packet_bytes)
        
        # Upload fuzzed data
        self._tftp_client.upload(filename, temp_file_path)
        
        os.unlink(temp_file_path)
        
        self.logger.debug(f"Uploaded {len(packet_bytes)} bytes as {filename}")
        return len(packet_bytes)

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Download file from TFTP server.
        
        Can be used to verify server responses or test download operations.
        Downloads from filename specified in context or 'test_file.bin'.
        """
        if not self.is_open or not self._tftp_client or not self._temp_dir:
            return None
        
        try:
            filename = getattr(self, '_download_filename', 'test_file.bin')
            
            temp_file_path = os.path.join(self._temp_dir, 'download_data')
            
            if timeout is not None:
                original_timeout = self._tftp_client.options.get('timeout')
                self._tftp_client.options['timeout'] = timeout
            
            try:
                self._tftp_client.download(filename, temp_file_path)
                
                with open(temp_file_path, 'rb') as f:
                    downloaded_data = f.read()
                
                os.unlink(temp_file_path)
                
                self.logger.debug(f"Downloaded {len(downloaded_data)} bytes from {filename}")
                return downloaded_data
                
            finally:
                # Restore original timeout
                if timeout is not None and original_timeout is not None:
                    self._tftp_client.options['timeout'] = original_timeout
            
        except (OSError, IOError, ConnectionError) as e:
            self.logger.error("TFTP download failed", e)
            return None

    def set_download_filename(self, filename: str) -> None:
        """Set filename for download operations."""
        self._download_filename = filename

    def close(self) -> None:
        """Clean up TFTP client and temporary directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                import shutil
                shutil.rmtree(self._temp_dir)
            except (OSError, IOError) as e:
                self.logger.warning(f"Failed to clean up temp directory: {e}")
        
        self._tftp_client = None
        self._temp_dir = None
        super().close()

    def get_socket_info(self) -> dict:
        """Get TFTP client information."""
        base_info = super().get_socket_info()
        base_info.update({
            "host": self.socket_cfg.host,
            "port": self.socket_cfg.port,
            "timeout": self.socket_cfg.timeout,
            "retries": self.socket_cfg.retries,
            "block_size": self.socket_cfg.block_size,
            "temp_directory": self._temp_dir
        })
        return base_info

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet=None) -> bytes:
        """
        Prepare TFTP client data for PCAP logging by wrapping in complete network stack.
        TFTP operates over UDP, so we create a UDP/IP/Ethernet packet.
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        
        # Create UDP packet for TFTP communication (typically port 69)
        udp_packet = UDP(
            sport=0,  # Client uses ephemeral port
            dport=self.socket_cfg.port
        ) / raw_bytes
        
        # Wrap in IP layer
        ip_packet = IP(
            src="127.0.0.1",  # Local client
            dst=self.socket_cfg.host
        ) / udp_packet
        
        # Wrap in Ethernet layer for PCAP compatibility
        eth_packet = Ether() / ip_packet
        
        return bytes(eth_packet)
