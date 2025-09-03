#!/usr/bin/env python3
"""
Modbus Server Socket Usage Example

This example demonstrates how to use the Modbus server socket for testing
Modbus client applications, HMIs, and SCADA systems.
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
from packetfuzz.sockets.modbus_server_socket import ModbusServerConfig


def run_modbus_server_example():
    """Example of using the Modbus server socket."""
    print("Running Modbus server example...")
    
    # Create configuration for the Modbus server with some initial register values
    config = ModbusServerConfig(
        bind_address="0.0.0.0",    # Listen on all interfaces
        port=5020,                  # Using non-standard port to avoid conflicts
        unit_id=1,                 # Unit ID / Slave ID
        block_size=100,            # Size of each register block
        debug_mode=True,           # Enable debug logging
        # Initialize some registers with values
        initial_holding_registers=[0, 100, 200, 300, 400, 500] + [0] * 94,
        initial_coils=[True, False, True, False, True] + [False] * 95
    )
    
    # Create a campaign with the Modbus server socket type
    campaign = FuzzingCampaign()
    campaign.socket_type = SocketType.MODBUS_SERVER
    campaign.socket_config = config
    campaign.debug_mode = True
    
    # Open the socket and start the server
    with campaign.get_socket().open() as server:
        server.start_listening()
        
        print(f"\nModbus server running on port {config.port}")
        print("Connect with a Modbus client to test")
        print("Example pymodbus client command:")
        print(f"python -m pymodbus.repl.client tcp --host localhost --port {config.port}")
        print("\nServer will run for 120 seconds. Press Ctrl+C to stop...")
        
        try:
            # Run the server and periodically update registers for demonstration
            for i in range(12):  # 12 x 10 seconds = 120 seconds
                time.sleep(10)
                
                # Update register values periodically
                server.update_holding_register(0, i * 10)  # Update register 0
                
                # Check for received requests
                print(f"\nIteration {i+1}, captured requests: {len(server.get_captured_requests())}")
                
                # Print register values
                registers = server.get_holding_registers(0, 5)
                coils = server.get_coils(0, 5)
                print(f"Current holding registers (0-4): {registers}")
                print(f"Current coils (0-4): {coils}")
                
                if server.get_captured_requests():
                    print("Last request:")
                    print(server.get_captured_requests()[-1])
                
        except KeyboardInterrupt:
            print("Interrupted by user")
        finally:
            print("Shutting down server...")


def main():
    """Main function to run the example."""
    parser = argparse.ArgumentParser(description="Modbus Server Example")
    parser.add_argument("--port", type=int, default=5020, help="Modbus server port")
    
    args = parser.parse_args()
    
    try:
        run_modbus_server_example()
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install pymodbus: pip install pymodbus>=3.1.0")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
