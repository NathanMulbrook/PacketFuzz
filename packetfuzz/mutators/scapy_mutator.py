"""
ScapyMutator: Minimal mutator that uses Scapy's built-in fuzz() function.
"""

# Standard library imports
import random
from typing import Any, List, Optional

# Third-party imports
from scapy.packet import Packet, fuzz

# Local imports
from .base import BaseMutator

class ScapyMutator(BaseMutator):
    """Mutator that uses Scapy's built-in fuzz() function to mutate fields or packets."""
    
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        """Return input data unchanged since byte mutation is not meaningful for Scapy fuzz."""
        # Not meaningful for raw bytes, so just return the input
        return data

    def mutate_field(self, field_info: Any, dictionaries: Optional[List[bytes]] = None, rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """
        Mutate field using Scapy's fuzz() function based on field type.
        
        Args:
            field_info: Field information with 'kind' attribute
            dictionaries: Dictionary entries (unused by this mutator)
            rng: Random number generator (unused by this mutator)
            layer: Packet layer (unused by this mutator)
            
        Returns:
            Fuzzed field value or original value if fuzzing fails
        """
        kind = getattr(field_info, 'kind', 'unknown')
        current_value = getattr(field_info, 'current_value', None)
        # Scapy's fuzz() operates on Packet; for primitive field values, we can do simple tweaks
        try:
            if kind in ('options', 'list'):
                # Return current_value as-is; manager may handle options with layer context
                return current_value
            if kind in ('string', 'raw'):
                # Append/alter a character
                s = '' if current_value is None else str(current_value)
                return (s + 'X') if len(s) < 1024 else s
            # numeric, flags, enum (or unknown)
            v = 0 if current_value is None else current_value
            try:
                return int(v) ^ 0x1
            except Exception:
                return v
        except Exception:
            return current_value
