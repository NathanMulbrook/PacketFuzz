#!/usr/bin/env python3
"""
FTP Socket Usage Example

Demonstrates how to use the FTP client and server socket types
for fuzzing data transferred over FTP connections.
"""

import sys
import os

# Add the packetfuzz module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.socket_types import SocketType
from packetfuzz.sockets.ftp_client_socket import FTPClientConfig
from packetfuzz.sockets.ftp_server_socket import FTPServerConfig


def example_ftp_client_config():
    """Example FTP client configuration for fuzzing uploads."""
    return FTPClientConfig(
        host='192.168.1.100',          # Target FTP server
        port=21,                       # FTP port
        username='anonymous',          # FTP username
        password='anonymous@',         # FTP password
        passive_mode=True,             # Use passive mode (recommended)
        timeout=30.0,                  # Connection timeout
        one_connection_per_file=False  # Reuse connection or reconnect per file
    )


def example_ftp_server_config():
    """Example FTP server configuration for fuzzing downloads."""
    return FTPServerConfig(
        bind_address='0.0.0.0',        # Listen on all interfaces
        port=21,                       # FTP port (requires root for port < 1024)
        username='fuzzer',             # FTP username for clients
        password='fuzzpass',           # FTP password for clients
        home_directory='/tmp/ftp_fuzz', # FTP root directory (None = auto temp)
        passive_ports=(60000, 65535),  # Passive mode port range
        max_connections=256,           # Max concurrent connections
        max_connections_per_ip=16,     # Max connections per IP
        one_connection_per_file=False  # Connection handling mode
    )


def example_campaign_usage():
    """Example of how to use FTP sockets in a fuzzing campaign."""
    
    print("=== FTP Socket Usage Examples ===")
    print()
    
    print("1. FTP Client Socket (for fuzzing uploads):")
    print("   - Use SocketType.FTP_CLIENT")
    print("   - Configure target FTP server details")
    print("   - Fuzzed data will be uploaded as files")
    print("   - Example configuration:")
    client_config = example_ftp_client_config()
    for attr, value in client_config.__dict__.items():
        print(f"     {attr}: {value}")
    print()
    
    print("2. FTP Server Socket (for fuzzing downloads):")
    print("   - Use SocketType.FTP_SERVER")
    print("   - Server will accept FTP client connections")
    print("   - Fuzzed data will be served for downloads")
    print("   - Example configuration:")
    server_config = example_ftp_server_config()
    for attr, value in server_config.__dict__.items():
        print(f"     {attr}: {value}")
    print()
    
    print("3. Usage in PacketFuzz campaign:")
    print("""
# For FTP client (upload fuzzing)
campaign = FuzzingCampaign(
    socket_type=SocketType.FTP_CLIENT,
    socket_config=FTPClientConfig(
        host='target.ftp.server',
        username='testuser',
        password='testpass'
    )
)

# For FTP server (download fuzzing)  
campaign = FuzzingCampaign(
    socket_type=SocketType.FTP_SERVER,
    socket_config=FTPServerConfig(
        port=2121,  # Non-privileged port
        username='fuzzer',
        password='fuzzpass'
    )
)
""")
    
    print("4. Key Features:")
    print("   ✓ Uses existing FTP implementations (ftplib + pyftpdlib)")
    print("   ✓ Supports both active and passive modes")
    print("   ✓ Configurable connection handling")
    print("   ✓ Automatic file naming for uploads")
    print("   ✓ Data capture for server uploads")
    print("   ✓ Fuzzed data serving for downloads")
    print()
    
    print("5. Dependencies:")
    print("   - ftplib (built-in Python library)")
    print("   - pyftpdlib (pip install pyftpdlib)")


if __name__ == '__main__':
    example_campaign_usage()
