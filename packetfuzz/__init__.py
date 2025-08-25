"""
PacketFuzz - A comprehensive packet fuzzing framework.

This package provides tools for network packet fuzzing, including:
- Campaign-based fuzzing framework
- PCAP-based fuzzing
- Dictionary management
- Mutation strategies
- Field-level and layer-level fuzzing
"""

from .fuzzing_framework import FuzzingCampaign, FuzzField, FuzzMutator, CallbackResult, CampaignContext
from .pcapfuzz import PcapFuzzCampaign, pcap_fuzz
from .mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from .dictionary_manager import DictionaryManager

__version__ = "1.0.0"
__all__ = [
    "FuzzingCampaign",
    "FuzzField", 
    "FuzzMutator",
    "CallbackResult",
    "CampaignContext",
    "PcapFuzzCampaign",
    "pcap_fuzz",
    "MutatorManager",
    "FuzzConfig",
    "FuzzMode",
    "DictionaryManager"
]
