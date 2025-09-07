#!/usr/bin/env python3
"""
Compatibility shim for PacketFuzz socket interface.

This module re-exports the minimal FuzzSocket ABC and the create_socket factory
from socket_interface to unify types across implementations.
"""

from __future__ import annotations

from .socket_interface import FuzzSocket, create as create_socket

__all__ = ["FuzzSocket", "create_socket", "BaseSocketConfig", "BaseSocket"]

import abc
from typing import Tuple


class BaseSocketConfig(abc.ABC):
    """Abstract base class for all socket configurations."""
    pass


class BaseSocket(abc.ABC):
    """
    Abstract base class for all socket types in PacketFuzz.
    Defines a common interface for socket operations.
    """

    @abc.abstractmethod
    def __init__(self, target_host: str, target_port: int, **kwargs):
        """
        Initializes the base socket with common parameters.

        Args:
            target_host: The target host IP address or hostname.
            target_port: The target port number.
            **kwargs: Additional keyword arguments for specific socket types.
        """
        self.target_host = target_host
        self.target_port = target_port

    @abc.abstractmethod
    def open(self) -> None:
        """
        Establishes the connection or prepares the socket for sending/receiving.
        """
        pass

    @abc.abstractmethod
    def send(self, data: bytes) -> int:
        """
        Sends data through the socket.

        Args:
            data: The bytes to send.

        Returns:
            The number of bytes sent.
        """
        pass

    @abc.abstractmethod
    def receive(self, buffer_size: int) -> bytes:
        """
        Receives data from the socket.

        Args:
            buffer_size: The maximum number of bytes to receive.

        Returns:
            The received bytes.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """
        Closes the socket connection.
        """
        pass

    @abc.abstractmethod
    def listen(self, backlog: int) -> None:
        """
        Starts listening for incoming connections.

        Args:
            backlog: The maximum number of queued connections.
        """
        pass

    @abc.abstractmethod
    def accept(self) -> Tuple['BaseSocket', Tuple[str, int]]:
        """
        Accepts an incoming connection.

        Returns:
            A tuple containing a new BaseSocket object for the accepted connection
            and the address of the client (host, port).
        """
        pass