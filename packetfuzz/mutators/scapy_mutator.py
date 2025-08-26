"""
ScapyMutator: Minimal mutator that uses Scapy's built-in fuzz() function.
"""

# Standard library imports
import random

# Third-party imports
from scapy.packet import Packet, fuzz

class ScapyMutator:
    """Mutator that uses Scapy's built-in fuzz() function to mutate fields or packets."""
    
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        """Return input data unchanged since byte mutation is not meaningful for Scapy fuzz."""
        # Not meaningful for raw bytes, so just return the input
        return data

    def mutate_field(self, field_info, current_value, dictionaries=None, rng: random.Random | None = None, layer: Packet | None = None):
        """
        Mutate field using Scapy's fuzz() function based on field type.
        
        Args:
            field_info: Field information with 'kind' attribute
            current_value: Current field value to mutate
            dictionaries: Dictionary entries (unused by this mutator)
            rng: Random number generator (unused by this mutator)
            layer: Packet layer (unused by this mutator)
            
        Returns:
            Fuzzed field value or original value if fuzzing fails
        """
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
