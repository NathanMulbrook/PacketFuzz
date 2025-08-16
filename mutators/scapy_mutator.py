"""
ScapyMutator: Minimal mutator that uses Scapy's built-in fuzz() function.
"""

from scapy.packet import Packet, fuzz
import random

class ScapyMutator:
    """
    Mutator that uses Scapy's built-in fuzz() to mutate fields or packets.
    """
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        # Not meaningful for raw bytes, so just return the input
        return data

    def mutate_field(self, field_info, current_value, dictionaries=None, rng: random.Random | None = None, layer: Packet | None = None):
        """Typed mutate_field: prefers Scapy fuzz() based on value kind."""
        kind = getattr(field_info, 'kind', 'unknown')
        try:
            if kind in ('options', 'list'):
                base = current_value if current_value is not None else []
                return fuzz(base)
            if kind in ('string', 'raw'):
                base = current_value if current_value is not None else ""
                return fuzz(base)
            # numeric, flags, enum (or unknown)
            base = current_value if current_value is not None else 0
            return fuzz(base)
        except Exception:
            return current_value
