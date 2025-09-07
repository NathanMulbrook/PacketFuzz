"""
Dictionary-Only Mutator

Provides mutation using only raw dictionary entries without additional mutations.
This mutator doesn't require libFuzzer and works purely with dictionary lookups.
"""

# Standard library imports
import logging
import random
import re
from typing import Any, List, Optional

# Third-party imports
from scapy.fields import AnyField, Field
from scapy.packet import Packet

# Local imports
from .base import BaseMutator, MutatorRegistry


class DictionaryOnlyMutator(BaseMutator):
    """
    Mutator that uses only raw dictionary values for mutation.
    
    Does not require libFuzzer C extension and works purely with dictionary lookups.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize DictionaryOnlyMutator with optional random seed."""
        super().__init__(seed)
        if seed is not None:
            random.seed(seed)
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[Any]] = None, max_size: int = 1024, seed: Optional[int] = None) -> bytes:
        """
        Mutate byte data using only dictionary entries.
        
        Args:
            data: Original byte data to mutate
            dictionaries: List of dictionary entries (bytes or str)
            max_size: Maximum size for truncation
            seed: Optional random seed for reproducible mutations
            
        Returns:
            Mutated byte data from dictionary entries
        """
        if not dictionaries:
            logging.getLogger(__name__).warning("No dictionaries provided to mutate_bytes; returning truncated input data.")
            return data[:max_size]
        if seed is not None:
            random.seed(seed)
        # Support both bytes and str entries
        selected_entry = random.choice(dictionaries)
        if isinstance(selected_entry, str):
            result_bytes = selected_entry.encode('utf-8', errors='ignore')
        elif isinstance(selected_entry, bytes):
            result_bytes = selected_entry
        else:
            raise TypeError(f"Dictionary entry must be str or bytes, got {type(selected_entry)}")
        return result_bytes[:max_size]

    # --- Helpers ---
    @staticmethod
    def _pick_entry(dictionaries: Optional[List[Any]], rng: Optional[random.Random] = None) -> Optional[Any]:
        if not dictionaries:
            return None
        r: random.Random = rng if isinstance(rng, random.Random) else random.Random()
        return r.choice(dictionaries)

    @staticmethod
    def _to_str_bytes(entry: Any) -> bytes:
        if isinstance(entry, bytes):
            return entry
        return str(entry).encode('utf-8', errors='ignore')

    @staticmethod
    def _parse_int_from_entry(entry: Any) -> Optional[int]:
        if isinstance(entry, (bytes, bytearray)):
            s = entry.decode('utf-8', errors='ignore')
        else:
            s = str(entry)
        # Extract first integer-like token (supports 0x, +/-)
        m = re.search(r"([+-]?0x[0-9a-fA-F]+|[+-]?\d+)", s)
        if not m:
            return None
        token = m.group(1)
        base = 16 if token.lower().startswith('0x') else 10
        return int(token, base)

    @staticmethod
    def _clamp(v: int, min_v: int, max_v: int) -> int:
        if v < min_v:
            return min_v
        if v > max_v:
            return max_v
        return v

    def mutate_field(self,
                     field_info: Any,
                     dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None,
                     layer: Optional[Any] = None) -> Any:
        """
        Mutate a field using only dictionary entries without additional algorithms.
        
        Args:
            field_info: Field metadata containing type and constraints
            dictionaries: List of dictionary entries to choose from
            rng: Random number generator for selection
            layer: Packet layer context (unused)
            
        Returns:
            Mutated field value selected from dictionaries or fallback defaults
        """
        kind = getattr(field_info, 'kind', None) or getattr(field_info, 'field_kind', 'unknown')
        field_name = getattr(field_info, 'field_name', 'unknown')
        current_value = getattr(field_info, 'current_value', None)
        r = rng if isinstance(rng, random.Random) else random.Random()

        logging.getLogger(__name__).debug(
            f"mutate_field called: field={field_name}, kind={kind}, dicts={len(dictionaries) if dictionaries else 0}"
        )

        if kind in ('numeric', 'flags', 'enum'):
            entry = self._pick_entry(dictionaries, r)
            val = self._parse_int_from_entry(entry) if entry is not None else None
            if val is None:
                # Fallback to common numeric values if no valid integer found in dictionary
                candidates = [0, 1, -1, 255, 256, 1024, 4096, 65535, 0x7fffffff, -0x80000000]
                val = r.choice(candidates)
            
            # Apply field size constraints
            min_v = getattr(field_info, 'min_value', 0)
            max_v = getattr(field_info, 'max_value', 0xFFFFFFFF)
            val = self._clamp(int(val), int(min_v), int(max_v))
            
            # Handle enum mapping for enum/flags fields
            if kind in ('enum', 'flags'):
                enum_map = getattr(field_info, 'enum_map', None)
                if enum_map and isinstance(enum_map, dict):
                    allowed_ints = list(enum_map.keys())
                    if allowed_ints and val not in allowed_ints:
                        val = allowed_ints[val % len(allowed_ints)]
            return val

        if kind == 'string':
            entry = self._pick_entry(dictionaries, r)
            if entry is None:
                return current_value
            s = self._to_str_bytes(entry)
            max_len = getattr(field_info, 'max_length', None)
            if isinstance(max_len, int) and max_len > 0:
                s = s[:max_len]
            return s.decode('utf-8', errors='ignore')

        #TODO these might need some work
        if kind in ('options', 'list'):
            return None

        if kind == 'raw':
            entry = self._pick_entry(dictionaries, r)
            if entry is None:
                return b""
            return self._to_str_bytes(entry)

        return current_value

