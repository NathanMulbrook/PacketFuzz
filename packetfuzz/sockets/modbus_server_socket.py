#!/usr/bin/env python3
"""
Modbus Server Socket Implementation

Provides a Modbus server implementation for fuzzing data sent to Modbus clients.
Useful for testing Modbus client applications, HMIs, and SCADA systems.
"""
from __future__ import annotations

import socket
import threading
import logging
import struct
import time
from typing import Optional, Dict, List, Any, Tuple, Union, TYPE_CHECKING
from dataclasses import dataclass, field

try:
    # Check if pymodbus is available
    import pymodbus
    from pymodbus.server import StartTcpServer, ServerStop
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
    from pymodbus.transaction import ModbusSocketFramer
    PYMODBUS_AVAILABLE = True
except ImportError:
    # Define stubs for type checking when pymodbus is not available
    class StartTcpServer:
        pass
    class ServerStop:
        pass
    class ModbusSequentialDataBlock:
        pass
    class ModbusSlaveContext:
        pass
    class ModbusServerContext:
        pass
    class ModbusSocketFramer:
        pass
    PYMODBUS_AVAILABLE = False

from .socket_interface import FuzzSocket
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class ModbusServerConfig(BaseSocketConfig):
    """Configuration for Modbus server socket."""
    bind_address: str = '0.0.0.0'
    port: int = 502
    # Modbus specific configuration
    unit_id: int = 1
    block_size: int = 100
    # Server options
    socket_timeout: Optional[float] = 5.0
    max_connections: int = 10
    # Initial register values
    initial_holding_registers: Optional[List[int]] = None
    initial_input_registers: Optional[List[int]] = None
    initial_coils: Optional[List[bool]] = None
    initial_discrete_inputs: Optional[List[bool]] = None
    # Fuzzing options
    fuzz_responses: bool = True
    capture_requests: bool = True
    request_history_size: int = 50
    # Debug options
    debug_mode: bool = False


class ModbusRequestHandler:
    """Handles Modbus requests for capturing and monitoring."""
    
    def __init__(self, server_socket: 'ModbusServerSocket'):
        self.server = server_socket
        self.logger = server_socket.logger
        self.debug_mode = server_socket.debug_mode
        self.requests = []
        self.max_requests = server_socket.socket_cfg.request_history_size
        self.lock = threading.Lock()
        
    def reset(self):
        """Reset request history."""
        with self.lock:
            self.requests.clear()
            
    def get_requests(self) -> List[Dict[str, Any]]:
        """Get copy of captured requests."""
        with self.lock:
            return self.requests.copy()
            
    def add_request(self, request_data: Dict[str, Any]):
        """Add a request to history."""
        if not request_data:
            return
            
        with self.lock:
            self.requests.append(request_data)
            # Trim history if needed
            while len(self.requests) > self.max_requests:
                self.requests.pop(0)
                
        if self.debug_mode:
            self.logger.debug(f"Modbus request captured: {request_data}")


class CustomModbusServer:
    """
    Custom Modbus server implementation that captures requests and allows
    fuzzing of responses.
    """
    
    def __init__(self, server_socket: 'ModbusServerSocket'):
        """Initialize the Modbus server."""
        self.server_socket = server_socket
        self.cfg = server_socket.socket_cfg
        self.logger = server_socket.logger
        self.debug_mode = server_socket.debug_mode
        
        self.server_thread = None
        self.server = None
        self.running = False
        self.request_handler = ModbusRequestHandler(server_socket)
        
        # Socket for interception when using standard pymodbus server
        self.intercept_socket = None
        self.intercept_thread = None
        
        # Data storage
        self._setup_datastore()
            
    def _setup_datastore(self):
        """Initialize the Modbus datastore with configured values."""
        # Initialize empty datastores
        block_size = self.cfg.block_size
        
        # Use provided initial values or create empty blocks
        hr_values = self.cfg.initial_holding_registers if self.cfg.initial_holding_registers else [0] * block_size
        ir_values = self.cfg.initial_input_registers if self.cfg.initial_input_registers else [0] * block_size
        co_values = self.cfg.initial_coils if self.cfg.initial_coils else [False] * block_size
        di_values = self.cfg.initial_discrete_inputs if self.cfg.initial_discrete_inputs else [False] * block_size
        
        # Create data blocks
        hr_block = ModbusSequentialDataBlock(0, hr_values)
        ir_block = ModbusSequentialDataBlock(0, ir_values)
        co_block = ModbusSequentialDataBlock(0, co_values)
        di_block = ModbusSequentialDataBlock(0, di_values)
        
        # Create slave context
        slave_context = ModbusSlaveContext(
            di=di_block,
            co=co_block,
            hr=hr_block,
            ir=ir_block,
            zero_mode=False
        )
        
        # Create server context with the configured unit ID
        self.context = ModbusServerContext(
            slaves={self.cfg.unit_id: slave_context},
            single=False
        )
        
    def start(self):
        """Start the Modbus server."""
        if self.running:
            return
            
        if not PYMODBUS_AVAILABLE:
            self.logger.error("pymodbus is not available. Cannot start Modbus server.")
            return False
            
        try:
            self.running = True
            
            # Create and start the server in a separate thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            
            # Wait a moment to ensure the server has started
            time.sleep(0.5)
            
            if self.debug_mode:
                self.logger.debug(f"Modbus server started on {self.cfg.bind_address}:{self.cfg.port}")
                
            return True
        except Exception as e:
            self.logger.error(f"Failed to start Modbus server: {e}")
            self.running = False
            return False
            
    def _run_server(self):
        """Run the Modbus server (called in thread)."""
        try:
            # Start the Modbus TCP server
            StartTcpServer(
                context=self.context,
                address=(self.cfg.bind_address, self.cfg.port),
                framer=ModbusSocketFramer,
                identity=None,
                allow_reuse_address=True,
                timeout=self.cfg.socket_timeout,
            )
        except Exception as e:
            if self.running:  # Only log if we're not shutting down intentionally
                self.logger.error(f"Modbus server error: {e}")
        finally:
            self.running = False
            
    def stop(self):
        """Stop the Modbus server."""
        if not self.running:
            return
            
        try:
            # Stop the server
            self.running = False
            ServerStop()
            
            # Wait for thread to terminate
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(2.0)
                
            if self.debug_mode:
                self.logger.debug("Modbus server stopped")
        except Exception as e:
            self.logger.error(f"Error stopping Modbus server: {e}")
    
    def get_context(self):
        """Get the Modbus server context."""
        return self.context
        
    def update_holding_register(self, address: int, value: int):
        """Update a holding register value."""
        try:
            slave_id = self.cfg.unit_id
            self.context[slave_id].setValues(3, address, [value])  # 3 = holding registers
            return True
        except Exception as e:
            self.logger.error(f"Failed to update holding register at {address}: {e}")
            return False
            
    def update_coil(self, address: int, value: bool):
        """Update a coil value."""
        try:
            slave_id = self.cfg.unit_id
            self.context[slave_id].setValues(1, address, [value])  # 1 = coils
            return True
        except Exception as e:
            self.logger.error(f"Failed to update coil at {address}: {e}")
            return False
            
    def get_holding_registers(self, address: int, count: int) -> List[int]:
        """Read holding registers."""
        try:
            slave_id = self.cfg.unit_id
            return self.context[slave_id].getValues(3, address, count)  # 3 = holding registers
        except Exception as e:
            self.logger.error(f"Failed to read holding registers at {address}: {e}")
            return []
            
    def get_input_registers(self, address: int, count: int) -> List[int]:
        """Read input registers."""
        try:
            slave_id = self.cfg.unit_id
            return self.context[slave_id].getValues(4, address, count)  # 4 = input registers
        except Exception as e:
            self.logger.error(f"Failed to read input registers at {address}: {e}")
            return []
            
    def get_coils(self, address: int, count: int) -> List[bool]:
        """Read coils."""
        try:
            slave_id = self.cfg.unit_id
            return self.context[slave_id].getValues(1, address, count)  # 1 = coils
        except Exception as e:
            self.logger.error(f"Failed to read coils at {address}: {e}")
            return []
            
    def get_discrete_inputs(self, address: int, count: int) -> List[bool]:
        """Read discrete inputs."""
        try:
            slave_id = self.cfg.unit_id
            return self.context[slave_id].getValues(2, address, count)  # 2 = discrete inputs
        except Exception as e:
            self.logger.error(f"Failed to read discrete inputs at {address}: {e}")
            return []


class ModbusServerSocket(FuzzSocket):
    """
    Modbus server socket implementation for fuzzing industrial control systems.
    
    Features:
    - Acts as a Modbus TCP server for client testing
    - Captures client requests for analysis
    - Can fuzz responses sent to Modbus clients
    - Provides full access to Modbus register types
    
    Use case: Testing Modbus clients, HMIs, and SCADA systems
    """

    def __init__(self, campaign) -> None:
        if not PYMODBUS_AVAILABLE:
            raise ImportError(
                "pymodbus is required for ModbusServerSocket. "
                "Please install it using 'pip install pymodbus>=3.1.0'"
            )
        
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: ModbusServerConfig = (
            cfg if isinstance(cfg, ModbusServerConfig) else ModbusServerConfig()
        )
        
        self._server: Optional[CustomModbusServer] = None
        self._raw_server_socket: Optional[socket.socket] = None
        self._running = False
        self.debug_mode = getattr(self.campaign, 'debug_mode', False) or self.socket_cfg.debug_mode
        
        # For injecting fuzzed responses
        self._response_queue = []
        self._response_lock = threading.Lock()

    def open(self) -> "ModbusServerSocket":
        """Initialize the Modbus server socket."""
        try:
            # Create server instance
            self.logger.info(f"Initializing Modbus server on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")
            self._server = CustomModbusServer(self)
            
            # Create a raw socket for compatibility with socket interface
            self._raw_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._raw_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Store the raw socket for compatibility
            self._sock = self._raw_server_socket
            
            return self
        except Exception as e:
            self.logger.error(f"Failed to initialize Modbus server: {e}")
            self.close()
            raise

    def start_listening(self, backlog: int = 5) -> None:
        """Start the Modbus server."""
        if not self._server:
            raise RuntimeError("Server not initialized. Call open() first.")
            
        # Start the server
        success = self._server.start()
        if not success:
            raise RuntimeError("Failed to start Modbus server")
            
        self._running = True
        self.logger.info(f"Modbus server running on {self.socket_cfg.bind_address}:{self.socket_cfg.port}")

    def send_packet(self, packet_bytes: bytes, context: 'CampaignContext') -> Optional[int]:
        """
        Queue a custom response packet to be sent to the next client request.
        
        This allows injecting fuzzed responses into the Modbus server's normal operation.
        """
        if not self._running:
            self.logger.error("Modbus server not running")
            return None
            
        # Store the packet for sending with the next client request
        with self._response_lock:
            self._response_queue.append(packet_bytes)
            
        if self.debug_mode:
            self.logger.debug(f"Queued fuzzed response: {packet_bytes.hex(' ')}")
            
        return len(packet_bytes)

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        In server mode, this returns a serialized representation of 
        the last client request.
        """
        if not self._server or not self._running:
            return None
            
        # Get captured requests
        requests = self._server.request_handler.get_requests()
        if not requests:
            return None
            
        # Return the most recent request
        last_request = requests[-1]
        
        # Return a serialized representation of the request
        # This is a simple implementation that could be enhanced
        try:
            import json
            return json.dumps(last_request).encode('utf-8')
        except Exception:
            return str(last_request).encode('utf-8')

    def get_captured_requests(self) -> List[Dict[str, Any]]:
        """Get all captured client requests."""
        if not self._server or not self._running:
            return []
            
        return self._server.request_handler.get_requests()
        
    def clear_captured_requests(self) -> None:
        """Clear the request history."""
        if self._server:
            self._server.request_handler.reset()

    def update_holding_register(self, address: int, value: int) -> bool:
        """Update a holding register value."""
        if not self._server or not self._running:
            return False
            
        return self._server.update_holding_register(address, value)
        
    def update_coil(self, address: int, value: bool) -> bool:
        """Update a coil value."""
        if not self._server or not self._running:
            return False
            
        return self._server.update_coil(address, value)
        
    def get_holding_registers(self, address: int, count: int) -> List[int]:
        """Read holding registers."""
        if not self._server or not self._running:
            return []
            
        return self._server.get_holding_registers(address, count)
        
    def get_coils(self, address: int, count: int) -> List[bool]:
        """Read coils."""
        if not self._server or not self._running:
            return []
            
        return self._server.get_coils(address, count)

    def close(self) -> None:
        """Stop and close the Modbus server."""
        # Stop the server
        if self._server:
            try:
                self._server.stop()
            except Exception as e:
                self.logger.error(f"Error stopping Modbus server: {e}")
            finally:
                self._server = None
                
        # Close raw socket
        if self._raw_server_socket:
            try:
                self._raw_server_socket.close()
            except Exception:
                pass
            finally:
                self._raw_server_socket = None
                self._sock = None
                
        self._running = False

    def get_socket_info(self) -> dict:
        """Get socket information for reporting."""
        base_info = super().get_socket_info()
        base_info.update({
            "bind_address": self.socket_cfg.bind_address,
            "port": self.socket_cfg.port,
            "unit_id": self.socket_cfg.unit_id,
            "running": self._running,
            "pymodbus_available": PYMODBUS_AVAILABLE,
            "captured_requests": len(self.get_captured_requests())
        })
        return base_info
