#!/usr/bin/env python3
"""
Modbus Client Socket Implementation

Wraps pymodbus to provide Modbus client functionality for fuzzing industrial
control systems, PLCs, and SCADA devices that communicate using the Modbus protocol.
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Dict, Any, TYPE_CHECKING, List, Union, Tuple
from dataclasses import dataclass, field

try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException, ConnectionException
    from pymodbus.pdu import ModbusRequest, ModbusResponse
    from pymodbus.transaction import ModbusSocketFramer
    PYMODBUS_AVAILABLE = True
except ImportError:
    # Define stubs for type checking when pymodbus is not available
    class ModbusTcpClient:
        pass
    class ModbusException(Exception):
        pass
    class ConnectionException(Exception):
        pass
    class ModbusRequest:
        pass
    class ModbusResponse:
        pass
    class ModbusSocketFramer:
        pass
    PYMODBUS_AVAILABLE = False

from .socket_interface import FuzzSocket
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class ModbusClientConfig(BaseSocketConfig):
    """Configuration for Modbus client socket."""
    host: str = '127.0.0.1'
    port: int = 502
    unit: int = 1  # Default unit/slave ID
    timeout: float = 3.0
    retry_on_empty: bool = True
    retries: int = 3
    retry_on_failure: bool = True
    close_comm_on_error: bool = False
    reconnect_delay: float = 0.5
    # Advanced configuration
    source_address: Optional[Tuple[str, int]] = None
    strict: bool = True
    # Additional options
    auto_reconnect: bool = True
    debug_mode: bool = False
    # Transaction options
    transaction_id_generator = None  # Use default
    transaction_timeout: float = 2.0
    # Default register sizes for read/write operations
    default_register_size: int = 1
    # Custom options
    one_connection_per_request: bool = False
    request_history_size: int = 10  # Number of requests to keep in history
    response_history_size: int = 10  # Number of responses to keep in history


class ModbusClientSocket(FuzzSocket):
    """
    Modbus client socket implementation for fuzzing industrial control systems.
    
    Features:
    - Uses pymodbus for Modbus protocol handling
    - Supports standard Modbus TCP function codes
    - Can fuzz Modbus requests sent to PLCs and industrial devices
    - Optional reconnection for each request
    
    Use case: Fuzzing industrial control systems, PLC communication testing
    """

    def __init__(self, campaign) -> None:
        if not PYMODBUS_AVAILABLE:
            raise ImportError(
                "pymodbus is required for ModbusClientSocket. "
                "Please install it using 'pip install pymodbus>=3.1.0'"
            )
        
        super().__init__(campaign)
        cfg = getattr(self.campaign, 'socket_config', None)
        self.socket_cfg: ModbusClientConfig = (
            cfg if isinstance(cfg, ModbusClientConfig) else ModbusClientConfig()
        )
        
        self._modbus_client: Optional[ModbusTcpClient] = None
        self._connected = False
        self._last_request: Optional[bytes] = None
        self._last_response: Optional[bytes] = None
        self._request_history: List[bytes] = []
        self._response_history: List[bytes] = []
        self.debug_mode = getattr(self.campaign, 'debug_mode', False) or self.socket_cfg.debug_mode

    def open(self) -> "ModbusClientSocket":
        """Connect to the Modbus server/device."""
        try:
            self.logger.info(f"Connecting to Modbus server at {self.socket_cfg.host}:{self.socket_cfg.port}")
            
            # Create Modbus TCP client
            self._modbus_client = ModbusTcpClient(
                host=self.socket_cfg.host,
                port=self.socket_cfg.port,
                framer=ModbusSocketFramer,
                timeout=self.socket_cfg.timeout,
                retries=self.socket_cfg.retries,
                retry_on_empty=self.socket_cfg.retry_on_empty,
                retry_on_failure=self.socket_cfg.retry_on_failure,
                strict=self.socket_cfg.strict,
                source_address=self.socket_cfg.source_address,
                reconnect_delay=self.socket_cfg.reconnect_delay,
                close_comm_on_error=self.socket_cfg.close_comm_on_error,
                transaction_id_generator=self.socket_cfg.transaction_id_generator
            )
            
            # Connect to the server
            connection_result = self._modbus_client.connect()
            if not connection_result:
                self.logger.error("Failed to connect to Modbus server")
                return self
                
            self._connected = True
            self.logger.info("Connected to Modbus server")
            
            # Store the underlying socket for compatibility
            self._sock = getattr(self._modbus_client, 'socket', None)
            
            return self
        except Exception as e:
            self.logger.error(f"Failed to connect to Modbus server: {e}")
            self.close()
            raise

    def _reconnect_if_needed(self) -> bool:
        """Reconnect to the Modbus server if not connected."""
        if self._connected and self._modbus_client and self._modbus_client.connected:
            return True
            
        if self.socket_cfg.auto_reconnect:
            try:
                self.logger.info("Reconnecting to Modbus server...")
                self.close()
                time.sleep(self.socket_cfg.reconnect_delay)
                self.open()
                return self._connected
            except Exception as e:
                self.logger.error(f"Failed to reconnect: {e}")
                return False
        return False

    def send_packet(self, packet_bytes: bytes, context: 'CampaignContext') -> Optional[int]:
        """
        Send a raw Modbus packet to the server.
        
        Note: This sends raw bytes over the socket and may not follow the Modbus
        protocol correctly if the packet_bytes are not properly formatted.
        For standard Modbus requests, use send_modbus_request instead.
        """
        if not self._reconnect_if_needed():
            self.logger.error("Not connected to Modbus server")
            return None
            
        if self.socket_cfg.one_connection_per_request:
            self.open()
            
        try:
            # Store the request
            self._last_request = packet_bytes
            self._request_history.append(packet_bytes)
            # Trim history if needed
            if len(self._request_history) > self.socket_cfg.request_history_size:
                self._request_history.pop(0)
                
            if self.debug_mode:
                self.logger.debug(f"Sending {len(packet_bytes)} bytes: {packet_bytes.hex(' ')}")
            
            # Send raw bytes to the socket
            if not hasattr(self._modbus_client, 'socket'):
                self.logger.error("No socket available in Modbus client")
                return None
                
            sock = self._modbus_client.socket
            if not sock:
                self.logger.error("Socket not initialized")
                return None
                
            bytes_sent = sock.send(packet_bytes)
            
            if self.socket_cfg.one_connection_per_request:
                # For one-connection-per-request mode, read response before closing
                try:
                    response = sock.recv(1024)
                    self._last_response = response
                    self._response_history.append(response)
                    # Trim history if needed
                    if len(self._response_history) > self.socket_cfg.response_history_size:
                        self._response_history.pop(0)
                    if self.debug_mode and response:
                        self.logger.debug(f"Received {len(response)} bytes: {response.hex(' ')}")
                except Exception as recv_err:
                    self.logger.error(f"Error receiving response: {recv_err}")
                finally:
                    self.close()
            
            return bytes_sent
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")
            self._connected = False
            return None

    def receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive raw response from the Modbus server.
        
        This is a low-level method that reads raw bytes from the socket.
        For structured Modbus responses, use send_modbus_request which handles both sending and receiving.
        """
        if not self._connected or not self._modbus_client or not getattr(self._modbus_client, 'socket', None):
            self.logger.error("Not connected to Modbus server")
            return None
            
        # If we already have a response from one_connection_per_request mode
        if self._last_response:
            response = self._last_response
            self._last_response = None
            return response
            
        try:
            # Use provided timeout or default from config
            actual_timeout = timeout if timeout is not None else self.socket_cfg.timeout
            
            # Set socket timeout
            sock = self._modbus_client.socket
            sock.settimeout(actual_timeout)
            
            # Read data
            response = sock.recv(1024)
            
            if response:
                # Store the response
                self._last_response = response
                self._response_history.append(response)
                # Trim history if needed
                if len(self._response_history) > self.socket_cfg.response_history_size:
                    self._response_history.pop(0)
                
                if self.debug_mode:
                    self.logger.debug(f"Received {len(response)} bytes: {response.hex(' ')}")
            
            return response
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}")
            return None

    def send_modbus_request(self, 
                          function_code: int,
                          address: int,
                          data: Optional[Union[int, List[int]]] = None,
                          count: Optional[int] = None,
                          unit: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Send a structured Modbus request using the pymodbus API.
        
        Args:
            function_code: Modbus function code (1-127)
            address: Register/coil address
            data: Data to write (for write operations)
            count: Number of registers/coils to read (for read operations)
            unit: Unit ID/Slave ID (defaults to config value)
            
        Returns:
            Dict with response data or None on failure
        """
        if not self._reconnect_if_needed():
            self.logger.error("Not connected to Modbus server")
            return None
            
        # Use default unit if not specified
        actual_unit = unit if unit is not None else self.socket_cfg.unit
        
        # Reconnect for each request if configured
        if self.socket_cfg.one_connection_per_request:
            self.open()
            
        try:
            response = None
            
            # Handle different function codes
            if function_code == 1:  # Read Coils
                response = self._modbus_client.read_coils(
                    address, count or self.socket_cfg.default_register_size, actual_unit)
            elif function_code == 2:  # Read Discrete Inputs
                response = self._modbus_client.read_discrete_inputs(
                    address, count or self.socket_cfg.default_register_size, actual_unit)
            elif function_code == 3:  # Read Holding Registers
                response = self._modbus_client.read_holding_registers(
                    address, count or self.socket_cfg.default_register_size, actual_unit)
            elif function_code == 4:  # Read Input Registers
                response = self._modbus_client.read_input_registers(
                    address, count or self.socket_cfg.default_register_size, actual_unit)
            elif function_code == 5:  # Write Single Coil
                response = self._modbus_client.write_coil(address, bool(data), actual_unit)
            elif function_code == 6:  # Write Single Register
                response = self._modbus_client.write_register(address, data, actual_unit)
            elif function_code == 15:  # Write Multiple Coils
                if not isinstance(data, list):
                    data = [bool(data)]
                response = self._modbus_client.write_coils(address, data, actual_unit)
            elif function_code == 16:  # Write Multiple Registers
                if not isinstance(data, list):
                    data = [data]
                response = self._modbus_client.write_registers(address, data, actual_unit)
            else:
                self.logger.error(f"Unsupported function code: {function_code}")
                return None
                
            if self.socket_cfg.one_connection_per_request:
                self.close()
                
            if response is None:
                self.logger.error("No response received")
                return None
                
            if response.isError():
                self.logger.error(f"Modbus error: {response}")
                return {"error": str(response)}
                
            # Convert response to dictionary based on function code
            result = {"function_code": function_code, "unit": actual_unit}
            
            if hasattr(response, 'bits'):
                result["bits"] = list(response.bits)
            if hasattr(response, 'registers'):
                result["registers"] = list(response.registers)
                
            if self.debug_mode:
                self.logger.debug(f"Modbus response: {result}")
                
            return result
            
        except ConnectionException as e:
            self.logger.error(f"Connection error: {e}")
            self._connected = False
            return None
        except ModbusException as e:
            self.logger.error(f"Modbus protocol error: {e}")
            return {"error": str(e)}
        except Exception as e:
            self.logger.error(f"Error sending Modbus request: {e}")
            return None

    def close(self) -> None:
        """Close the Modbus connection."""
        if self._modbus_client:
            try:
                self._modbus_client.close()
            except Exception as e:
                self.logger.error(f"Error closing Modbus connection: {e}")
            finally:
                self._modbus_client = None
                self._connected = False
                self._sock = None

    def get_socket_info(self) -> dict:
        """Get socket information for reporting."""
        base_info = super().get_socket_info()
        base_info.update({
            "host": self.socket_cfg.host,
            "port": self.socket_cfg.port,
            "unit": self.socket_cfg.unit,
            "connected": self._connected,
            "one_connection_per_request": self.socket_cfg.one_connection_per_request,
            "pymodbus_available": PYMODBUS_AVAILABLE
        })
        return base_info
