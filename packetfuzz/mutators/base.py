"""
Base mutator interface for Scapy LibFuzzer

Defines the common interface that all mutators must implement.
"""

# Standard library imports
import logging
import random
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Union

logger = logging.getLogger(__name__)


class BaseMutator(ABC):
    """
    Abstract base class for all mutators.
    
    Provides a common interface for different mutation strategies
    (libFuzzer C extension, pure Python, etc.)
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize the mutator with optional random seed."""
        if seed is not None:
            random.seed(seed)
    
    @abstractmethod
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """
        Mutate raw byte data
        
        Args:
            data: The byte data to mutate
            dictionaries: Optional dictionary entries to use for mutation
            
        Returns:
            Mutated byte data
        """
        pass

    @abstractmethod
    def mutate_field(self,
                     field_info: Any,
                     current_value: Any,
                     dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None,
                     layer: Optional[Any] = None) -> Any:
        """
        Mutate a field value with context.

        Args:
            field_info: Dataclass-like object describing field type, name, constraints
            current_value: The current Python value of the field
            dictionaries: Optional dictionary entries for this field
            rng: Optional RNG
            layer: The Scapy layer instance that owns this field (optional)

        Returns:
            A Python value suitable for assignment to this field (or None/Skip to defer)
        """
        raise NotImplementedError()
