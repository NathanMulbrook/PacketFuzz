#!/usr/bin/env python3
"""
FTP Server Socket Implementation

Wraps pyftpdlib to provide FTP server functionality for fuzzing data
received from FTP clients. Supports both active and passive modes.
"""
from __future__ import annotations

import threading
import tempfile
import os
import io
from typing import Optional, TYPE_CHECKING, Any
from dataclasses import dataclass

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from .socket_interface import FuzzSocket
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class FTPServerConfig(BaseSocketConfig):
    """Configuration for FTP server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 21
    username: str = 'fuzzer'
    password: str = 'fuzzpass'
    home_directory: Optional[str] = None  # If None, creates temp directory
    passive_ports: tuple[int, int] = (60000, 65535)
    max_connections: int = 256
    max_connections_per_ip: int = 16
    one_connection_per_file: bool = False


class FuzzingFTPHandler(FTPHandler):
    """Custom FTP handler that captures fuzzed data for the fuzzing framework."""
    
    def __init__(self, conn, server, ioloop=None):
        super().__init__(conn, server, ioloop)
        # These will be set dynamically
        self.fuzz_socket = None
        self.received_data = io.BytesIO()
    
    def ftp_STOR(self, file):
        """Handle STOR command - capture uploaded data for fuzzing."""
        # Call original STOR implementation first
        result = super().ftp_STOR(file)
        
        # Try to capture the uploaded data after the fact
        if hasattr(self, 'fuzz_socket') and self.fuzz_socket:
            try:
                # Get file path and read data
                if hasattr(self, 'fs') and self.fs:
                    file_path = self.fs.realpath(file)
                    if file_path and os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            data = f.read()
                        self.fuzz_socket._capture_uploaded_data(data, file)
            except Exception:
                # Don't let capture errors break FTP operation
                pass
        
        return result

    def ftp_RETR(self, file):
        """Handle RETR command - serve fuzzed data for download."""
        if hasattr(self, 'fuzz_socket') and self.fuzz_socket:
            fuzzed_data = self.fuzz_socket._get_fuzzed_data_for_download(file)
            if fuzzed_data and hasattr(self, 'fs') and self.fs:
                # Create temporary file with fuzzed data
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                temp_file.write(fuzzed_data)
                temp_file.flush()
                temp_file.close()
                
                # Get the real file path
                try:
                    original_path = self.fs.realpath(file)
                    backup_path = None
                    
                    if os.path.exists(original_path):
                        # Backup original
                        backup_path = original_path + '.backup'
                        os.rename(original_path, backup_path)
                    
                    # Copy fuzzed file
                    os.rename(temp_file.name, original_path)
                    
                    try:
                        # Call original RETR implementation
                        result = super().ftp_RETR(file)
                    finally:
                        # Restore original file
                        if backup_path and os.path.exists(backup_path):
                            os.rename(backup_path, original_path)
                        elif os.path.exists(original_path):
                            os.unlink(original_path)
                    
                    return result
                except Exception:
                    # Clean up temp file on error
                    try:
                        os.unlink(temp_file.name)
                    except:
                        pass
        
        # Fall back to original implementation
        return super().ftp_RETR(file)


class FTPServerSocket(FuzzSocket):
    """
    FTP server socket implementation for fuzzing data received from FTP clients.
    
    Features:
    - Uses pyftpdlib for full FTP server functionality
    - Captures uploaded data for fuzzing analysis
    - Can serve fuzzed data for download operations
    - Supports active and passive modes
    - Configurable passive port range
    
    Use case: Server-side FTP fuzzing, analyzing client uploads
    """

    def __init__(self, campaign) -> None:
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: FTPServerConfig = cfg if isinstance(cfg, FTPServerConfig) else FTPServerConfig()
        
        self._server: Optional[FTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._temp_dir: Optional[str] = None
        self._running = False
        
        # Data capture for fuzzing
        self._captured_data: list[tuple[bytes, str]] = []  # (data, filename)
        self._fuzzed_download_data: Optional[bytes] = None

    def open(self) -> "FTPServerSocket":
        """Create and configure FTP server."""
        try:
            # Set up home directory
            if self.socket_cfg.home_directory:
                home_dir = self.socket_cfg.home_directory
            else:
                self._temp_dir = tempfile.mkdtemp(prefix='ftp_fuzz_')
                home_dir = self._temp_dir
            
            # Create authorizer
            authorizer = DummyAuthorizer()
            authorizer.add_user(
                self.socket_cfg.username,
                self.socket_cfg.password,
                home_dir,
                perm='elradfmw'  # Full permissions for fuzzing
            )
            
            # Create custom handler
            handler = FuzzingFTPHandler
            handler.authorizer = authorizer
            
            # Try to set passive ports if supported
            try:
                handler.passive_ports = self.socket_cfg.passive_ports
            except (AttributeError, TypeError):
                pass  # Ignore if not supported

            # Create server
            self._server = FTPServer((self.socket_cfg.bind_address, self.socket_cfg.port), handler)
            
            # Try to set connection limits if supported
            try:
                setattr(self._server, 'max_connections', self.socket_cfg.max_connections)
            except (AttributeError, TypeError):
                pass
            try:
                setattr(self._server, 'max_connections_per_ip', self.socket_cfg.max_connections_per_ip)
            except (AttributeError, TypeError):
                pass
            
            # Store reference to this socket for handler instances
            setattr(self._server, '_fuzz_socket_ref', self)
            
            self.logger.info(f"FTP server configured on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
            return self
            
        except Exception as e:
            error_msg = f"Failed to create FTP server on {self.socket_cfg.bind_address}:{self.socket_cfg.port}"
            self.logger.error(error_msg, e)
            raise OSError(f"{error_msg}: {e}")

    def start_listening(self, backlog: int = 5) -> None:
        """Start the FTP server in a background thread."""
        if not self._server:
            raise RuntimeError("FTP server not configured")
        
        if self._running:
            self.logger.warning("FTP server already running")
            return
        
        def server_loop():
            try:
                self.logger.info("Starting FTP server...")
                if self._server:
                    self._server.serve_forever()
            except Exception as e:
                self.logger.error("FTP server error", e)
        
        self._server_thread = threading.Thread(target=server_loop, daemon=True)
        self._server_thread.start()
        self._running = True
        
        self.logger.info(f"FTP server listening on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")

    @property
    def is_open(self) -> bool:
        """Check if FTP server is configured."""
        return self._server is not None

    @property
    def raw(self) -> Optional[FTPServer]:
        """Return underlying FTP server for compatibility."""
        return self._server

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        """
        Set fuzzed data to be served for download operations.
        
        The packet_bytes will be served when clients download files.
        """
        self._fuzzed_download_data = packet_bytes
        self.logger.debug(f"Set {len(packet_bytes)} bytes of fuzzed data for downloads")
        return len(packet_bytes)

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Get data captured from client uploads.
        
        Returns the most recently uploaded data from FTP clients.
        """
        if self._captured_data:
            data, filename = self._captured_data[-1]
            self.logger.debug(f"Retrieved {len(data)} bytes from upload: {filename}")
            return data
        return None

    def get_captured_uploads(self) -> list[tuple[bytes, str]]:
        """Get all captured upload data with filenames."""
        return self._captured_data.copy()

    def clear_captured_data(self) -> None:
        """Clear captured upload data."""
        self._captured_data.clear()

    def _capture_uploaded_data(self, data: bytes, filename: str) -> None:
        """Internal method called by FuzzingFTPHandler to capture uploads."""
        self._captured_data.append((data, filename))
        self.logger.debug(f"Captured {len(data)} bytes from upload: {filename}")

    def _get_fuzzed_data_for_download(self, filename: str) -> Optional[bytes]:
        """Internal method called by FuzzingFTPHandler to get fuzzed download data."""
        if self._fuzzed_download_data:
            self.logger.debug(f"Serving {len(self._fuzzed_download_data)} bytes of fuzzed data for: {filename}")
            return self._fuzzed_download_data
        return None

    def close(self) -> None:
        """Stop FTP server and clean up."""
        self._running = False
        
        if self._server:
            try:
                self._server.close_all()
            except Exception:
                pass
        
        if self._server_thread and self._server_thread.is_alive():
            # Give server time to shutdown gracefully
            self._server_thread.join(timeout=2.0)
        
        # Clean up temp directory
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                import shutil
                shutil.rmtree(self._temp_dir)
            except Exception as e:
                self.logger.warning(f"Failed to clean up temp directory: {e}")
        
        self._server = None
        self._server_thread = None
        super().close()

    def get_socket_info(self) -> dict:
        """Get FTP server information."""
        base_info = super().get_socket_info()
        base_info.update({
            "bind_address": self.socket_cfg.bind_address,
            "port": self.socket_cfg.port,
            "username": self.socket_cfg.username,
            "home_directory": self.socket_cfg.home_directory or self._temp_dir,
            "passive_ports": self.socket_cfg.passive_ports,
            "running": self._running,
            "captured_uploads": len(self._captured_data)
        })
        return base_info
