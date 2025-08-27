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
from .base import BaseMutator


class DictionaryOnlyMutator(BaseMutator):
    """
    Mutator that uses only raw dictionary values for mutation.
    
    Does not require libFuzzer C extension and works purely with dictionary lookups.
    """
    
    def __init__(self, seed: Optional[int] = None):
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
        r = rng or random
        return r.choice(dictionaries)

    @staticmethod
    def _to_str_bytes(entry: Any) -> bytes:
        if isinstance(entry, bytes):
            return entry
        return str(entry).encode('utf-8', errors='ignore')

    @staticmethod
    def _parse_int_from_entry(entry: Any) -> Optional[int]:
        try:
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
        except Exception:
            return None

    @staticmethod
    def _clamp(v: int, min_v: int, max_v: int) -> int:
        if v < min_v:
            return min_v
        if v > max_v:
            return max_v
        return v

    def mutate_field(self,
                     field_info: Any,
                     current_value: Any,
                     dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None,
                     layer: Optional[Any] = None) -> Any:
        kind = getattr(field_info, 'kind', 'unknown')
        r = rng or random

        # Numeric-like (includes flags as integers)
        if kind in ('numeric', 'flags', 'enum'):
            entry = self._pick_entry(dictionaries, r)
            val = self._parse_int_from_entry(entry) if entry is not None else None
            # If no numeric in dictionary, generate interesting values
            if val is None:
                candidates = [0, 1, -1, 255, 256, 1024, 4096, 65535, 0x7fffffff, -0x80000000]
                val = r.choice(candidates)
            # Range/bit width clamp
            min_v = getattr(field_info, 'min_value', 0)
            max_v = getattr(field_info, 'max_value', 0xFFFFFFFF)
            val = self._clamp(int(val), int(min_v), int(max_v))
            # Enum mapping: if EnumField has specific values, optionally remap
            enum_map = getattr(field_info, 'enum_map', None)
            if enum_map and isinstance(enum_map, dict):
                # Enum maps typically use integer keys -> name strings
                allowed_ints = list(enum_map.keys())
                if allowed_ints:
                    if val not in allowed_ints:
                        try:
                            val = allowed_ints[val % len(allowed_ints)]
                        except Exception:
                            pass
            return val

        # String-like
        if kind == 'string':
            entry = self._pick_entry(dictionaries, r)
            if entry is None:
                return ""  # empty string permissible
            s = self._to_str_bytes(entry)
            max_len = getattr(field_info, 'max_length', None)
            if isinstance(max_len, int) and max_len > 0:
                s = s[:max_len]
            try:
                return s.decode('utf-8', errors='ignore')
            except Exception:
                return s.decode('latin-1', errors='ignore')

        # Options/list-like: Prefer letting Scapy generate sensible structures later.
        # But per user request, use Scapy mutator via manager for options; here we return a marker None
        if kind in ('options', 'list'):
            return None  # Manager may invoke ScapyMutator for options specifically

        # Raw-like
        if kind == 'raw':
            entry = self._pick_entry(dictionaries, r)
            if entry is None:
                return b""
            b = self._to_str_bytes(entry)
            return b

        # Unknown kinds: do nothing
        return current_value
