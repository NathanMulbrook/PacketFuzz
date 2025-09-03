#!/usr/bin/env python3
from __future__ import annotations

import logging
import socket
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

from .socket_interface import FuzzSocket
from .config import BaseSocketConfig

if TYPE_CHECKING:
    from ..fuzzing_framework import CampaignContext


@dataclass
class RawEthernetConfig(BaseSocketConfig):
    """Configuration for raw ethernet socket."""
    interface: str = 'eth0'


class RawEthernetSocket(FuzzSocket):
    """
    AF_PACKET/SOCK_RAW sender for Layer 2 frames.
    Binds to interface from config and uses send() on raw bytes.
    """

    def open(self) -> "RawEthernetSocket":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        cfg = getattr(self.campaign, 'socket_config', None)
        interface = cfg.interface if isinstance(cfg, RawEthernetConfig) else 'eth0'
        s.bind((interface, 0))
        self._sock = s
        return self

    def send_packet(self, packet_bytes: bytes, context: "CampaignContext") -> Optional[int]:
        if not self._sock:
            return None
        try:
            return self._sock.send(packet_bytes)
        except Exception as e:
            logging.getLogger(__name__).error(f"[RawEthernetSocket] send failed: {e}")
            return None

    def close(self) -> None:
        try:
            super().close()
        except Exception as e:
            logging.getLogger(__name__).warning(f"[RawEthernetSocket] close error: {e}")