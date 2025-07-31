"""
ScapyMutator: Minimal mutator that uses Scapy's built-in fuzz() function.
"""

from scapy.packet import Packet, fuzz

class ScapyMutator:
    """
    Mutator that uses Scapy's built-in fuzz() to mutate fields or packets.
    """
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        # Not meaningful for raw bytes, so just return the input
        return data

    def mutate_field(self, value, field_desc=None, layer=None, dictionary_entries=None):
        try:
            return fuzz(value)
        except Exception:
            return value
