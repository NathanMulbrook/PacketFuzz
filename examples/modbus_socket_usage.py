#!/usr/bin/env python3
"""
Modbus Socket Usage Example

This example demonstrates how to use the Modbus client socket for fuzzing
industrial control systems, PLCs, and SCADA devices.
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
from packetfuzz.sockets.modbus_client_socket import ModbusClientConfig


def run_modbus_client_example():
    """Example of using the Modbus client socket."""
    print("Running Modbus client example...")
    
    # Create configuration for the Modbus client
    config = ModbusClientConfig(
        host="localhost",     # Target Modbus server/device
        port=502,             # Standard Modbus TCP port
        unit=1,               # Unit ID/Slave ID
        timeout=5.0,          # Connection timeout
        debug_mode=True       # Enable debug logging
    )
    
    # Create a campaign with the Modbus client socket type
    campaign = FuzzingCampaign()
    campaign.socket_type = SocketType.MODBUS_CLIENT
    campaign.socket_config = config
    campaign.debug_mode = True
    
    # Open the socket
    with campaign.get_socket().open() as modbus:
        print("Connected to Modbus server")
        
        print("\n1. Reading coils (function code 1):")
        # Read 10 coils starting at address 0
        result = modbus.send_modbus_request(function_code=1, address=0, count=10)
        print(f"Result: {result}")
        
        print("\n2. Reading holding registers (function code 3):")
        # Read 5 holding registers starting at address 0
        result = modbus.send_modbus_request(function_code=3, address=0, count=5)
        print(f"Result: {result}")
        
        print("\n3. Writing a single register (function code 6):")
        # Write value 42 to register at address 0
        result = modbus.send_modbus_request(function_code=6, address=0, data=42)
        print(f"Result: {result}")
        
        print("\n4. Writing multiple registers (function code 16):")
        # Write values [10, 20, 30] to registers starting at address 10
        result = modbus.send_modbus_request(function_code=16, address=10, data=[10, 20, 30])
        print(f"Result: {result}")
        
        print("\n5. Raw packet sending example:")
        # Example of a raw Modbus TCP packet:
        # Transaction ID: 0x0001
        # Protocol ID: 0x0000 (Modbus)
        # Length: 0x0006 (6 bytes)
        # Unit ID: 0x01
        # Function code: 0x03 (Read Holding Registers)
        # Starting Address: 0x0000
        # Quantity of registers: 0x0005
        raw_packet = bytes([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x03,        # Function code
            0x00, 0x00,  # Starting Address
            0x00, 0x05   # Quantity of registers
        ])
        
        bytes_sent = modbus.send_packet(raw_packet, campaign.context)
        print(f"Sent {bytes_sent} bytes")
        
        # Wait for response
        time.sleep(0.5)
        response = modbus.receive_response()
        if response:
            print(f"Response: {response.hex(' ')}")
        else:
            print("No response received")


def main():
    """Main function to run the example."""
    parser = argparse.ArgumentParser(description="Modbus Socket Example")
    parser.add_argument("--host", default="localhost", help="Modbus server host")
    parser.add_argument("--port", type=int, default=502, help="Modbus server port")
    parser.add_argument("--unit", type=int, default=1, help="Unit/Slave ID")
    
    args = parser.parse_args()
    
    print(f"Connecting to Modbus server at {args.host}:{args.port}, unit ID {args.unit}")
    
    try:
        run_modbus_client_example()
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install pymodbus: pip install pymodbus>=3.1.0")
    except ConnectionRefusedError:
        print(f"Connection refused to {args.host}:{args.port}")
        print("Make sure a Modbus server is running at the specified address.")
        print("\nTip: You can run a simple Modbus server for testing using:")
        print("    python -m pymodbus.server --modbus-server tcp")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
