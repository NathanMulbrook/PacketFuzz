#!/usr/bin/env python3
"""
Telnet Socket Usage Example

This example demonstrates how to use both the Telnet client and server sockets
for fuzzing Telnet protocol communications.
"""

import sys
import time
import argparse
from pathlib import Path

# Add the parent directory to sys.path so we can import packetfuzz
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
if project_root not in [Path(p).resolve() for p in sys.path]:
    sys.path.insert(0, str(project_root))

from packetfuzz import FuzzingCampaign
from packetfuzz.socket_types import SocketType
from packetfuzz.sockets.telnet_client_socket import TelnetClientConfig
from packetfuzz.sockets.telnet_server_socket import TelnetServerConfig


def run_telnet_client_example():
    """Example of using the Telnet client socket."""
    print("Running Telnet client example...")
    
    # Create configuration for the Telnet client
    config = TelnetClientConfig(
        host="localhost",      # Target Telnet server
        port=23,               # Standard Telnet port
        timeout=5.0,           # Connection timeout
        username=None,         # No authentication in this example
        password=None
    )
    
    # Create a campaign with the Telnet client socket type
    campaign = FuzzingCampaign(
        name="telnet_client_example",
        socket_type=SocketType.TELNET_CLIENT,
        socket_config=config,
        debug_mode=True
    )
    
    # Open the socket
    with campaign.get_socket() as telnet:
        # Send some commands
        print("Sending commands to Telnet server...")
        commands = [
            b"help\n",
            b"ls -la\n",
            b"whoami\n",
            b"exit\n"
        ]
        
        for cmd in commands:
            print(f"Sending: {cmd.decode().strip()}")
            bytes_sent = telnet.send_packet(cmd, campaign.context)
            print(f"Bytes sent: {bytes_sent}")
            
            # Wait for response
            time.sleep(0.5)
            response = telnet.receive_response()
            if response:
                print(f"Response: {response.decode(errors='replace')}")
            else:
                print("No response received")
            
            # Small delay between commands
            time.sleep(1)


def run_telnet_server_example():
    """Example of using the Telnet server socket."""
    print("Running Telnet server example...")
    
    # Create configuration for the Telnet server
    config = TelnetServerConfig(
        bind_address="0.0.0.0",   # Listen on all interfaces
        port=2323,                # Using a non-privileged port for the example
        max_connections=5,        # Maximum number of concurrent connections
        timeout=30.0,             # Client timeout
        banner="Welcome to PacketFuzz Telnet Example Server\r\n",
        prompt="telnet> "
    )
    
    # Create a campaign with the Telnet server socket type
    campaign = FuzzingCampaign(
        name="telnet_server_example",
        socket_type=SocketType.TELNET_SERVER,
        socket_config=config,
        debug_mode=True
    )
    
    # Open the socket and start listening
    with campaign.get_socket() as server:
        server.start_listening(5)
        
        print(f"Telnet server running on port {config.port}")
        print("Connect with: telnet localhost 2323")
        print("Server will run for 60 seconds. Press Ctrl+C to stop...")
        
        try:
            # Run the server for 60 seconds
            for _ in range(60):
                time.sleep(1)
                
                # Check for received data
                data = server.receive_response()
                if data:
                    print(f"Received data: {data.decode(errors='replace').strip()}")
                    
                    # Example of sending a broadcast message to all clients
                    server.send_packet(b"Server broadcast: Hello to all clients!\r\n", campaign.context)
        except KeyboardInterrupt:
            print("Interrupted by user")
        finally:
            print("Shutting down server...")


def main():
    """Main function to run the example."""
    parser = argparse.ArgumentParser(description="Telnet Socket Examples")
    parser.add_argument("mode", choices=["client", "server"],
                        help="Run as Telnet client or server")
    
    args = parser.parse_args()
    
    if args.mode == "client":
        run_telnet_client_example()
    else:
        run_telnet_server_example()


if __name__ == "__main__":
    main()
