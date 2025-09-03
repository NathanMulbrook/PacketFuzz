#!/usr/bin/env python3
"""
TFTP Socket Usage Example

Demonstrates how to use the TFTP client and server socket types
for fuzzing data transferred over TFTP connections.
"""

import sys
import os

# Add the packetfuzz module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.socket_types import SocketType
from packetfuzz.sockets.tftp_client_socket import TFTPClientConfig
from packetfuzz.sockets.tftp_server_socket import TFTPServerConfig


def example_tftp_client_config():
    """Example TFTP client configuration for fuzzing uploads."""
    return TFTPClientConfig(
        host='192.168.1.100',      # Target TFTP server
        port=69,                   # TFTP port (UDP)
        timeout=5.0,               # Operation timeout
        retries=5,                 # Number of retries
        block_size=512             # TFTP block size
    )


def example_tftp_server_config():
    """Example TFTP server configuration for fuzzing downloads."""
    return TFTPServerConfig(
        bind_address='0.0.0.0',    # Listen on all interfaces
        port=69,                   # TFTP port (requires root for port < 1024)
        root_directory='/tmp/tftp_fuzz',  # TFTP root directory (None = auto temp)
        timeout=5.0,               # Session timeout
        retries=5,                 # Number of retries
        enable_upload=True,        # Allow client uploads
        enable_download=True       # Allow client downloads
    )


def example_campaign_usage():
    """Example of how to use TFTP sockets in a fuzzing campaign."""
    
    print("=== TFTP Socket Usage Examples ===")
    print()
    
    print("1. TFTP Client Socket (for fuzzing uploads):")
    print("   - Use SocketType.TFTP_CLIENT")
    print("   - Configure target TFTP server details")
    print("   - Fuzzed data will be uploaded as files")
    print("   - UDP-based protocol (simpler than FTP)")
    print("   - Example configuration:")
    client_config = example_tftp_client_config()
    for attr, value in client_config.__dict__.items():
        print(f"     {attr}: {value}")
    print()
    
    print("2. TFTP Server Socket (for fuzzing downloads):")
    print("   - Use SocketType.TFTP_SERVER")
    print("   - Server will accept TFTP client connections")
    print("   - Fuzzed data will be served for downloads")
    print("   - Example configuration:")
    server_config = example_tftp_server_config()
    for attr, value in server_config.__dict__.items():
        print(f"     {attr}: {value}")
    print()
    
    print("3. Usage in PacketFuzz campaign:")
    print("""
# For TFTP client (upload fuzzing)
campaign = FuzzingCampaign(
    socket_type=SocketType.TFTP_CLIENT,
    socket_config=TFTPClientConfig(
        host='target.tftp.server',
        port=69,
        timeout=10.0
    )
)

# For TFTP server (download fuzzing)  
campaign = FuzzingCampaign(
    socket_type=SocketType.TFTP_SERVER,
    socket_config=TFTPServerConfig(
        port=6969,  # Non-privileged port
        enable_upload=True,
        enable_download=True
    )
)
""")
    
    print("4. TFTP vs FTP Comparison:")
    print("   TFTP Advantages:")
    print("   ✓ Simpler protocol (UDP-based)")
    print("   ✓ No authentication required")
    print("   ✓ Smaller protocol overhead")
    print("   ✓ Good for embedded/IoT fuzzing")
    print()
    print("   FTP Advantages:")
    print("   ✓ More reliable (TCP-based)")
    print("   ✓ Authentication support")
    print("   ✓ Better for large file transfers")
    print("   ✓ More enterprise features")
    print()
    
    print("5. Key Features:")
    print("   ✓ Uses tftpy library for complete TFTP implementation")
    print("   ✓ Simple UDP-based protocol")
    print("   ✓ Configurable timeouts and retries")
    print("   ✓ Automatic file naming for uploads")
    print("   ✓ Directory monitoring for server uploads")
    print("   ✓ Fuzzed data serving for downloads")
    print()
    
    print("6. Dependencies:")
    print("   - tftpy (pip install tftpy)")
    print()
    
    print("7. Common Use Cases:")
    print("   - IoT device firmware upload fuzzing")
    print("   - Network boot (PXE) fuzzing")
    print("   - Simple file transfer protocol testing")
    print("   - Embedded system configuration fuzzing")


if __name__ == '__main__':
    example_campaign_usage()
