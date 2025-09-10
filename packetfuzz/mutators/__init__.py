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
from enum import Enum
from pathlib import Path
import importlib
import pkgutil

from .base import BaseMutator, MutatorRegistry

def _load_mutators():
    """Automatically discover and load all mutator modules"""
    package_path = Path(__file__).parent
    for module_file in package_path.glob("*_mutator.py"):
        module_name = module_file.stem
        try:
            importlib.import_module(f".{module_name}", package=__name__)
        except (ImportError, ModuleNotFoundError) as e:
            logging.getLogger(__name__).warning(f"Failed to load mutator {module_name}: {e}")

_load_mutators()

logger = logging.getLogger(__name__)

__all__ = ["BaseMutator", "MutatorRegistry"]
