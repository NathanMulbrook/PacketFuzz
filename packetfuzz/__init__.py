"""
PacketFuzz - A comprehensive packet fuzzing framework.

This package provides tools for network packet fuzzing, including:
- Campaign-based fuzzing framework
- PCAP-based fuzzing
- Dictionary management
- Mutation strategies
- Field-level and layer-level fuzzing
"""

from .fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult, CampaignContext
from .mutators import MutatorRegistry
from .pcapfuzz import PcapFuzzCampaign
from .mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from .dictionary_manager import DictionaryManager

__version__ = "1.0.0"
__all__ = [
    "FuzzingCampaign",
    "FuzzField", 
    "MutatorRegistry",
    "CallbackResult",
    "CampaignContext",
    "PcapFuzzCampaign",
    "MutatorManager",
    "FuzzConfig",
    "FuzzMode",
    "DictionaryManager"
]
