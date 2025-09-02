"""
Mutators Package - Field and Packet Mutation Strategies

This package provides different mutation strategies for packet fuzzing:

- BaseMutator: Abstract base class for all mutators
- LibFuzzerMutator: High-performance mutations using libFuzzer C extension  
- ScapyMutator: Simple mutations using Scapy's built-in fuzz() function
- DictionaryOnlyMutator: Pure dictionary-based mutations without additional algorithms

All mutators implement the common BaseMutator interface and are managed
by the MutatorManager for field type compatibility and systematic fuzzing.
"""

import logging

from .base import BaseMutator
from .libfuzzer_mutator import LibFuzzerMutator

# Configure module-level logger
logger = logging.getLogger(__name__)

__all__ = ["BaseMutator", "LibFuzzerMutator"]
