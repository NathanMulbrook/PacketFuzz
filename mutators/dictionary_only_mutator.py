"""
Dictionary-Only Mutator

Provides mutation using only raw dictionary entries without additional mutations.
This mutator doesn't require libFuzzer and works purely with dictionary lookups.
"""

import random
import logging
from typing import List, Optional, Any
from scapy.packet import Packet
from scapy.fields import Field, AnyField
from mutators.base import BaseMutator


class DictionaryOnlyMutator(BaseMutator):
    """
    Mutator that uses only raw dictionary values for mutation.
    Does not require libFuzzer C extension.
    """
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        if seed is not None:
            random.seed(seed)
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[Any]] = None, max_size: int = 1024, seed: Optional[int] = None) -> bytes:
        """Mutate byte data using only dictionary entries. Supports bytes or str entries, optional truncation and seeding."""
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
