"""
Base mutator interface for Scapy LibFuzzer

Defines the common interface that all mutators must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Union, Optional
import random
import logging

logger = logging.getLogger(__name__)


class BaseMutator(ABC):
    """
    Abstract base class for all mutators
    
    Provides a common interface for different mutation strategies
    (libFuzzer C extension, pure Python, etc.)
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize the mutator with optional random seed"""
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
