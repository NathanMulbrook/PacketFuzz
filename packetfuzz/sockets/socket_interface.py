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
        self.campaign = campaign
    
    def get_target(self, default: str = '127.0.0.1') -> str:
        """Get target address with fallback default."""
        return getattr(self.campaign, 'target', default)
    
    def get_port(self, default: int = 80) -> int:
        """Get port with fallback default."""
        return getattr(self.campaign, 'port', default)
    
    def get_interface(self, default: str = 'eth0') -> str:
        """Get network interface with fallback default."""
        return getattr(self.campaign, 'interface', default)
    
    def get_bind_address(self, default: str = '0.0.0.0') -> str:
        """Get bind address for server mode with fallback default."""
        return getattr(self.campaign, 'bind_address', default)


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
        self.campaign = campaign
        self.socket_type: Optional[SocketType] = getattr(campaign, "_normalize_socket_type", None) and campaign._normalize_socket_type() or None
        self._sock: Optional[socket.socket] = None
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

    def get_socket_info(self) -> dict:
        return {
            "socket_type": self.socket_type.value if self.socket_type else "unknown",
            "target": getattr(self.campaign, "target", None),
            "interface": getattr(self.campaign, "interface", None),
            "is_open": self.is_open,
        }

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def __enter__(self) -> 'FuzzSocket':
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __str__(self) -> str:
        st = self.socket_type.value if self.socket_type else "unknown"
        return f"{self.__class__.__name__}({st} -> {getattr(self.campaign, 'target', None)})"

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

    st = campaign._normalize_socket_type()
    if st is None:
        raise ValueError(f"Invalid socket_type: {getattr(campaign, 'socket_type', None)}")

    # Registry-based socket creation for cleaner factory pattern
    socket_registry = {
        SocketType.RAW_ETHERNET: ('raw_ethernet_socket', 'RawEthernetSocket'),
        SocketType.RAW_IP: ('raw_ip_socket', 'RawIPSocket'),
        SocketType.RAW_TCP: ('raw_tcp_socket', 'RawTCPSocket'),
        SocketType.RAW_UDP: ('raw_udp_socket', 'RawUDPSocket'),
        SocketType.MANAGED_TCP: ('managed_tcp_socket', 'ManagedTCPSocket'),
        SocketType.MANAGED_UDP: ('managed_udp_socket', 'ManagedUDPSocket'),
        SocketType.CANBUS: ('canbus_socket', 'CANBusSocket'),
        SocketType.LISTENING_TCP: ('listening_tcp_socket', 'ListeningTCPSocket'),
        SocketType.LISTENING_UDP: ('listening_udp_socket', 'ListeningUDPSocket'),
    }
    
    if st not in socket_registry:
        raise NotImplementedError(f"Socket type not implemented yet: {st}")
    
    module_name, class_name = socket_registry[st]
    
    # Dynamic import to avoid circular dependencies
    try:
        if module_name == 'raw_ethernet_socket':
            from .raw_ethernet_socket import RawEthernetSocket
            return RawEthernetSocket(campaign)
        elif module_name == 'raw_ip_socket':
            from .raw_ip_socket import RawIPSocket
            return RawIPSocket(campaign)
        elif module_name == 'raw_tcp_socket':
            from .raw_tcp_socket import RawTCPSocket
            return RawTCPSocket(campaign)
        elif module_name == 'raw_udp_socket':
            from .raw_udp_socket import RawUDPSocket
            return RawUDPSocket(campaign)
        elif module_name == 'managed_tcp_socket':
            from .managed_tcp_socket import ManagedTCPSocket
            return ManagedTCPSocket(campaign)
        elif module_name == 'managed_udp_socket':
            from .managed_udp_socket import ManagedUDPSocket
            return ManagedUDPSocket(campaign)
        elif module_name == 'canbus_socket':
            from .canbus_socket import CANBusSocket
            return CANBusSocket(campaign)
        elif module_name == 'listening_tcp_socket':
            from .listening_tcp_socket import ListeningTCPSocket
            return ListeningTCPSocket(campaign)
        elif module_name == 'listening_udp_socket':
            from .listening_udp_socket import ListeningUDPSocket
            return ListeningUDPSocket(campaign)
        else:
            raise NotImplementedError(f"Socket implementation not found: {module_name}")
    except ImportError as e:
        raise ImportError(f"Failed to import socket implementation for {st}: {e}")