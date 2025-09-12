#!/usr/bin/env python3
"""
PacketFuzz Socket Interface

Minimal ABC for socket wrappers ("fuzz_socket" objects).
Intended usage:
- Framework stores this object on context.fuzz_socket
- For backward compatibility, context.socket may point to fuzz_socket.raw

Factory 'create' is included here and currently implements RAW_ETHERNET only.
Other types will be added in their own files and enabled here incrementally.
"""

from __future__ import annotations

import socket
import logging
from abc import ABC, abstractmethod
from typing import Optional, Any, TYPE_CHECKING

from ..socket_types import SocketType

if TYPE_CHECKING:
    from ..fuzzing_framework import FuzzingCampaign, CampaignContext


class SocketConfig:
    """Standardized configuration access for sockets."""
    
    def __init__(self, campaign: 'FuzzingCampaign') -> None:
        self.socket_config = getattr(campaign, 'socket_config', None)
        # Import socket config types once during initialization
        self.config_types = self._load_socket_config_types()
    
    def _load_socket_config_types(self):
        """Load socket config types once to avoid repeated imports."""
        config_types = {}
        # Delay imports to avoid cycles
        try:
            from .managed_udp_socket import ManagedUDPConfig
            from .managed_tcp_socket import ManagedTCPConfig
            from .raw_udp_socket import RawUDPConfig
            from .raw_ip_socket import RawIPConfig
            from .raw_tcp_socket import RawTCPConfig

            config_types["target_configs"] = (ManagedUDPConfig, ManagedTCPConfig, RawUDPConfig, RawIPConfig, RawTCPConfig)
            config_types["port_configs"] = (ManagedUDPConfig, ManagedTCPConfig, RawUDPConfig)
        except ImportError as e:
            # Config classes not available in this environment; return empty tuples but log the cause.
            logging.getLogger(__name__).warning(f"Socket config types not available: {e}")
            config_types["target_configs"] = ()
            config_types["port_configs"] = ()
            
        return config_types
    
    def get_target(self, default: str = '127.0.0.1') -> str:
        """Get target address from socket_config when present, else default."""
        if isinstance(self.socket_config, self.config_types.get("target_configs", ())):
            return getattr(self.socket_config, 'target', default)
        return default
    
    def get_port(self, default: int = 80) -> int:
        """Get port from socket_config when present, else default."""
        if isinstance(self.socket_config, self.config_types.get("port_configs", ())):
            return getattr(self.socket_config, 'port', default)
        return default
    
    def get_interface(self, default: str = 'eth0') -> str:
        """Get network interface from socket_config when present, else default."""
        return getattr(self.socket_config, 'interface', default) if self.socket_config else default
    
    def get_bind_address(self, default: str = '0.0.0.0') -> str:
        """Get bind address from socket_config when present, else default."""
        return getattr(self.socket_config, 'bind_address', default) if self.socket_config else default


class SocketLogger:
    """Standardized logging for sockets."""
    
    def __init__(self, socket_name: str) -> None:
        self.logger = logging.getLogger(__name__)
        self.prefix = f"[{socket_name}]"
    
    def info(self, message: str) -> None:
        """Log info message with socket prefix."""
        self.logger.info(f"{self.prefix} {message}")
    
    def warning(self, message: str) -> None:
        """Log warning message with socket prefix."""
        self.logger.warning(f"{self.prefix} {message}")
    
    def error(self, message: str, exception: Optional[Exception] = None) -> None:
        """Log error message with socket prefix."""
        if exception:
            self.logger.error(f"{self.prefix} {message}: {exception}")
        else:
            self.logger.error(f"{self.prefix} {message}")
    
    def debug(self, message: str) -> None:
        """Log debug message with socket prefix."""
        self.logger.debug(f"{self.prefix} {message}")


class FuzzSocket(ABC):
    """
    Base interface for all PacketFuzz sockets.
    Keep it small and easy to integrate with the existing fuzzing loop.
    """

    def __init__(self, campaign: 'FuzzingCampaign') -> None:
        self.socket_type: Optional[SocketType] = None  # Will be set by factory
        self._sock: Optional[socket.socket] = None
        self.socket_config = getattr(campaign, 'socket_config', None)
        self.debug_mode: bool = getattr(campaign, 'debug_mode', False)
        # Helper objects for standardized operations
        self.config = SocketConfig(campaign)
        self.logger = SocketLogger(self.__class__.__name__)

    @property
    def is_open(self) -> bool:
        return self._sock is not None

    @property
    def raw(self) -> Optional[socket.socket]:
        """Underlying OS socket for compatibility."""
        return self._sock

    @abstractmethod
    def open(self) -> 'FuzzSocket':
        """
        Create/configure the underlying OS socket and return self.
        Must set self._sock.
        """
        raise NotImplementedError

    @abstractmethod
    def send_packet(self, packet_bytes: bytes, context: 'CampaignContext') -> Optional[int]:
        """
        Transmit packet_bytes using self._sock.
        Return number of bytes sent or None on failure.
        """
        raise NotImplementedError

    def receive_response(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Default: not supported."""
        return None

    def start_listening(self, backlog: int = 5) -> None:
        """Start listening for incoming connections. Override in listening sockets."""
        raise NotImplementedError("This socket type does not support listening")

    def accept_connection(self, timeout: Optional[float] = None) -> Optional[tuple['FuzzSocket', tuple[str, int]]]:
        """Accept an incoming connection. Override in listening sockets."""
        raise NotImplementedError("This socket type does not support accepting connections")

    def prepare_for_pcap_logging(self, raw_bytes: bytes, original_packet: Any = None, iteration: int = 0) -> bytes:
        """
        Prepare packet for PCAP logging by creating a complete packet with proper lower layers.
        
        Each socket type knows exactly what lower layer protocol stack it needs.
        This method creates a complete packet structure with the raw fuzzed bytes 
        as payload, ensuring PCAP compatibility while preserving fuzz integrity.
        
        Args:
            raw_bytes: Serialized fuzzed packet bytes to embed in PCAP structure
            original_packet: Original packet structure for reference (optional)
            
        Returns:
            Complete packet bytes ready for PCAP logging
        """
        # Default implementation: minimal Ethernet frame
        from scapy.layers.l2 import Ether, Raw
        fallback = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") / Raw(load=raw_bytes)
        return bytes(fallback)

    def get_socket_info(self) -> dict:
        return {
            "socket_type": self.socket_type.value if self.socket_type else "unknown",
            "interface": getattr(self.socket_config, "interface", None),
            "is_open": self.is_open,
        }

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except (OSError, socket.error):
                pass  # Benign close failures can be ignored

    def __enter__(self) -> 'FuzzSocket':
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __str__(self) -> str:
        st = self.socket_type.value if self.socket_type else "unknown"
        return f"{self.__class__.__name__}({st})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(socket_type={self.socket_type}, is_open={self.is_open})"


def create(campaign: 'FuzzingCampaign') -> FuzzSocket:
    """
    Factory for fuzz_socket creation.
    Usage pattern:
        fs = create(campaign).open()
        context.fuzz_socket = fs
        context.socket = fs.raw  # optional backward-compat
    Supports user override via campaign.socket_provider or campaign.socket_factory.
    """
    # User-supplied factory override
    provider = getattr(campaign, "socket_provider", None) or getattr(campaign, "socket_factory", None)
    if callable(provider):
        fs = provider(campaign)
        if not isinstance(fs, FuzzSocket):
            raise TypeError("socket_provider/socket_factory must return a FuzzSocket")
        return fs

    # Determine socket type from socket_config
    st = None
    if campaign.socket_config is not None:
        # Import config types to build mapping
        config_to_socket_type = {}
        try:
            from .raw_ethernet_socket import RawEthernetConfig
            from .raw_ip_socket import RawIPConfig
            from .raw_tcp_socket import RawTCPConfig
            from .raw_udp_socket import RawUDPConfig
            from .managed_tcp_socket import ManagedTCPConfig
            from .managed_udp_socket import ManagedUDPConfig
            from .canbus_socket import CANBusConfig
            from .server_tcp_socket import ServerTCPConfig
            from .server_udp_socket import ServerUDPConfig
            
            config_to_socket_type = {
                RawEthernetConfig: SocketType.RAW_ETHERNET,
                RawIPConfig: SocketType.RAW_IP,
                RawTCPConfig: SocketType.RAW_TCP,
                RawUDPConfig: SocketType.RAW_UDP,
                ManagedTCPConfig: SocketType.MANAGED_TCP,
                ManagedUDPConfig: SocketType.MANAGED_UDP,
                CANBusConfig: SocketType.CANBUS,
                ServerTCPConfig: SocketType.SERVER_TCP,
                ServerUDPConfig: SocketType.SERVER_UDP,
            }
            
            # Find socket type based on config class
            config_class = campaign.socket_config.__class__
            st = config_to_socket_type.get(config_class)
                
        except ImportError:
            pass  # Config classes not available
    
    if st is None:
        raise ValueError(f"Cannot determine socket_type from socket_config={getattr(campaign, 'socket_config', None)}. Please provide a valid socket_config.")

    # Registry-based socket creation for cleaner factory pattern
    socket_registry = {
        SocketType.RAW_ETHERNET: ('raw_ethernet_socket', 'RawEthernetSocket'),
        SocketType.RAW_IP: ('raw_ip_socket', 'RawIPSocket'),
        SocketType.RAW_TCP: ('raw_tcp_socket', 'RawTCPSocket'),
        SocketType.RAW_UDP: ('raw_udp_socket', 'RawUDPSocket'),
        SocketType.MANAGED_TCP: ('managed_tcp_socket', 'ManagedTCPSocket'),
        SocketType.MANAGED_UDP: ('managed_udp_socket', 'ManagedUDPSocket'),
        SocketType.CANBUS: ('canbus_socket', 'CANBusSocket'),
        SocketType.SERVER_TCP: ('server_tcp_socket', 'ServerTCPSocket'),
        SocketType.SERVER_UDP: ('server_udp_socket', 'ServerUDPSocket'),
        SocketType.FTP_CLIENT: ('ftp_client_socket', 'FTPClientSocket'),
        SocketType.FTP_SERVER: ('ftp_server_socket', 'FTPServerSocket'),
        SocketType.TFTP_CLIENT: ('tftp_client_socket', 'TFTPClientSocket'),
        SocketType.TFTP_SERVER: ('tftp_server_socket', 'TFTPServerSocket'),
        SocketType.TELNET_CLIENT: ('telnet_client_socket', 'TelnetClientSocket'),
        SocketType.TELNET_SERVER: ('telnet_server_socket', 'TelnetServerSocket'),
        SocketType.MODBUS_CLIENT: ('modbus_client_socket', 'ModbusClientSocket'),
        SocketType.MODBUS_SERVER: ('modbus_server_socket', 'ModbusServerSocket'),
    }
    
    if st not in socket_registry:
        raise NotImplementedError(f"Socket type not implemented yet: {st}")
    
    module_name, class_name = socket_registry[st]
    
    # Dynamic import using importlib for cleaner implementation
    try:
        # Import the module dynamically
        import importlib
        socket_module = importlib.import_module(f".{module_name}", package="packetfuzz.sockets")
        
        # Get the socket class from the module
        socket_class = getattr(socket_module, class_name)
        
        # Create socket instance
        socket_instance = socket_class(campaign)
        
        # Set the socket_type from the inferred or provided type
        socket_instance.socket_type = st
        
        return socket_instance
    except ImportError as e:
        raise ImportError(f"Failed to import socket implementation for {st}: {e}")
    except AttributeError as e:
        raise ImportError(f"Socket class {class_name} not found in module {module_name}: {e}")