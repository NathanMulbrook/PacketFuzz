#!/usr/bin/env python3
"""
Dictionary Management for PacketFuzzing

Provides dictionary mapping with support for embedded packet configuration,
user overrides, and hierarchical fallback patterns.

Simplified unified implementation that maintains the same user interface.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging

from scapy.packet import Packet

# Import default configurations
from default_mappings import (
    FIELD_DEFAULT_VALUES,
    FIELD_TYPE_WEIGHTS,
    FIELD_NAME_WEIGHTS,
    FIELD_ADVANCED_WEIGHTS,
    FIELD_TYPE_DICTIONARIES,
    FIELD_NAME_DICTIONARIES,
    FIELD_ADVANCED_DICTIONARIES
)

# Configuration constants
# Controls whether default values from FIELD_DEFAULT_VALUES are included
# When False (default): Only use values from FuzzFields and campaign config
# When True: Include default values from imported files as fallback
INCLUDE_DEFAULT_VALUES = False

logger = logging.getLogger(__name__)


class DictionaryManager:
    """
    Unified dictionary manager with support for embedded packet configuration,
    user overrides, and hierarchical fallback.
    
    Configuration Priority (highest to lowest):
    1. Packet field embedded configuration (field.dictionary)
    2. User configuration overrides from config file
    3. Default protocol mappings (only if INCLUDE_DEFAULT_VALUES=True)
    """
    
    def __init__(self, user_config_file: Optional[str] = None, fuzzdb_path: Optional[str] = None):
        """
        Initialize the dictionary manager.
        
        Args:
            user_config_file: Path to user configuration file  
            fuzzdb_path: Path to FuzzDB directory (auto-detected if None)
        """
        self.fuzzdb_path = fuzzdb_path or self._find_fuzzdb_path()
        # Store default field values for optional use (controlled by INCLUDE_DEFAULT_VALUES)
        self.field_values = FIELD_DEFAULT_VALUES.copy()
        # Note: Default behavior now excludes these values unless INCLUDE_DEFAULT_VALUES=True
    
    def __str__(self) -> str:
        return f"DictionaryManager(fuzzdb={bool(self.fuzzdb_path)})"
    
    def __repr__(self) -> str:
        return f"DictionaryManager(fuzzdb_path='{self.fuzzdb_path}')"
    
    def _find_fuzzdb_path(self) -> Optional[str]:
        """Auto-detect FuzzDB path"""
        possible_paths = [
            Path("fuzzdb"),
            Path("../fuzzdb"),
            Path("/usr/share/fuzzdb"),
            Path("/opt/fuzzdb"),
            Path.home() / "fuzzdb"
        ]
        for path in possible_paths:
            if path.exists() and path.is_dir():
                return str(path)
        return None
    
    def _resolve_path(self, path: str) -> str:
        """Resolve dictionary path to absolute path"""
        p = Path(path)
        if p.is_absolute():
            return str(p)
        # Convert fuzzdb/ relative paths to absolute if fuzzdb_path available
        if path.startswith("fuzzdb/") and self.fuzzdb_path:
            return str(Path(self.fuzzdb_path) / path[7:])
        # Fallback: try to find fuzzdb directory from current location
        current = Path(__file__).parent
        while current != current.parent:
            fuzzdb_path = current / "fuzzdb"
            if fuzzdb_path.exists():
                return str(fuzzdb_path / path)
            current = current.parent
        # Last resort: relative to project root
        return str(Path(__file__).parent / path)
    
    @staticmethod
    def expand_macro(entry: str) -> List[str]:
        """
        Expand macro references (e.g., '@string') to their dictionary lists.
        """
        from default_mappings import MACROS
        if entry.startswith("@"):  # Macro reference
            macro_name = entry[1:]
            return MACROS.get(macro_name, [])
        return [entry]

    def _extract_field_info(self, packet: Packet, field_name: str) -> tuple:
        """
        Extract field type and properties from packet's field config.
        Returns (field_type: str, properties: dict)
        """
        field_type = ""
        properties = {}
        if hasattr(packet, 'get_field_fuzz_config'):
            field_config = packet.get_field_fuzz_config(field_name)
            if field_config:
                if hasattr(field_config, 'type') and isinstance(field_config.type, str):
                    field_type = field_config.type
                if hasattr(field_config, 'properties') and isinstance(field_config.properties, dict):
                    properties = field_config.properties
        return field_type, properties
    
    # Resolves advanced dictionary mappings for a field (merge/override logic for dictionary lists)
    def _resolve_advanced_dictionary(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "merge") -> list:
        """
        Advanced dictionary resolver supporting combining modes: override, merge.
        - mode can be set globally (global_mode) or per-entry (entry['mode'])
        - If multiple entries match, combine according to the highest-priority mode found (per-entry overrides global)
        """
        length = properties.get("length")
        context = properties.get("context")
        matches = []
        modes = []
        
        # Scan all mapping entries to find matches based on field criteria
        for adv in mapping_list:
            match = adv.get("match", {})
            # Multi-criteria matching: all specified criteria must pass
            if (
                ("name" not in match or match["name"] == field_name) and
                ("type" not in match or match["type"] == field_type) and
                # Handle length comparison with optional '>' prefix for ranges
                ("length" not in match or (length is not None and str(length) == str(match["length"]).replace('>', ''))) and
                ("context" not in match or match["context"] == context)
            ):
                if "dictionaries" in adv:
                    # Expand macro placeholders to actual dictionary file paths
                    expanded = []
                    for d in adv["dictionaries"]:
                        expanded.extend(DictionaryManager.expand_macro(d))
                    matches.append(expanded)
                    modes.append(adv.get("mode"))
        
        if not matches:
            return []
            
        # Resolution mode precedence: per-entry mode > global_mode
        mode = next((m for m in modes if m), global_mode)
        if mode == "merge":
            # Combine all matches and remove duplicates while preserving order
            return list(dict.fromkeys([v for sublist in matches for v in sublist]))
        # Default: override (last match wins)
        return matches[-1]

    # Resolves advanced weight mappings for a field (supports override, sum, average, max, min)
    def _resolve_advanced_weight(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "override") -> float:
        """
        Advanced weight resolver supporting combining modes: override, sum, average, max, min.
        - mode can be set globally (global_mode) or per-entry (entry['mode'])
        - If multiple entries match, combine according to the highest-priority mode found (per-entry overrides global)
        """
        length = properties.get("length")
        context = properties.get("context")
        matches = []
        modes = []
        for adv in mapping_list:
            match = adv.get("match", {})
            if (
                ("name" not in match or match["name"] == field_name) and
                ("type" not in match or match["type"] == field_type) and
                ("length" not in match or (length is not None and str(length) == str(match["length"]).replace('>', ''))) and
                ("context" not in match or match["context"] == context)
            ):
                if "weight" in adv:
                    matches.append(float(adv["weight"]))
                    modes.append(adv.get("mode"))
        if not matches:
            return None  # No match found, continue to other weight resolution steps
        # Determine mode: per-entry mode takes precedence, else use global_mode
        mode = None
        for m in modes:
            if m:
                mode = m
                break
        if not mode:
            mode = global_mode
        if mode == "sum":
            return sum(matches)
        elif mode == "average":
            return sum(matches) / len(matches)
        elif mode == "max":
            return max(matches)
        elif mode == "min":
            return min(matches)
        # Default: override (last match wins)
        return matches[-1]

    # Resolves advanced value mappings for a field (merge/override logic for value lists)
    def _resolve_advanced_values(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "override") -> list:
        """
        Advanced values resolver supporting combining modes: override, merge.
        - mode can be set globally (global_mode) or per-entry (entry['mode'])
        - If multiple entries match, combine according to the highest-priority mode found (per-entry overrides global)
        """
        length = properties.get("length")
        context = properties.get("context")
        matches = []
        modes = []
        for adv in mapping_list:
            match = adv.get("match", {})
            if (
                ("name" not in match or match["name"] == field_name) and
                ("type" not in match or match["type"] == field_type) and
                ("length" not in match or (length is not None and str(length) == str(match["length"]).replace('>', ''))) and
                ("context" not in match or match["context"] == context)
            ):
                if "values" in adv:
                    matches.append(adv["values"])
                    modes.append(adv.get("mode"))
        if not matches:
            return []
        # Determine mode: per-entry mode takes precedence, else use global_mode
        mode = next((m for m in modes if m), global_mode)
        if mode == "merge":
            # Flatten and deduplicate
            return list(dict.fromkeys([v for sublist in matches for v in sublist]))
        # Default: override (last match wins)
        return matches[-1]

    def get_merged_field_mapping(self, 
                                 default_mapping: list, 
                                 user_mapping_file: Optional[str] = None, 
                                 inline_overrides: Optional[list] = None, 
                                 merge_mode: Optional[str] = None,
                                 mode: str = 'dictionary') -> list:
        """
        Load and merge advanced field mappings (for weights, dictionaries, or values).

        Default behavior:
            - For dictionaries: merge lists from all sources (default, user, inline)
            - For values: override (last/highest-priority source wins)
            - For weights: override (last/highest-priority source wins)
        """
        import importlib.util
        import json
        import os

        # Set default merge_mode based on mode if not explicitly provided
        if merge_mode is None:
            merge_mode = 'merge' if mode == 'dictionary' else 'override'

        def load_mapping_file(path):
            # Check if the mapping file exists
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Mapping file not found: {path}")
            # Support loading from JSON
            if path.endswith('.json'):
                with open(path, 'r') as f:
                    return json.load(f)
            # Support loading from Python file (expects FIELD_ADVANCED_DICTIONARIES)
            elif path.endswith('.py'):
                spec = importlib.util.spec_from_file_location("user_mapping", path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load Python mapping file: {path}")
                user_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(user_mod)
                return getattr(user_mod, 'FIELD_ADVANCED_DICTIONARIES', [])
            else:
                raise ValueError(f"Unsupported mapping file type: {path}")

        # 1. Start with the default mapping (lowest priority)
        merged = list(default_mapping)
        # 2. If a user mapping file is provided, load and merge/override
        if user_mapping_file:
            user_map = load_mapping_file(user_mapping_file)
            if merge_mode == 'override':
                # 2.1 User mapping completely overrides default
                merged = list(user_map)
            else:
                # 2.2 Merge: add user entries not already present
                merged = merged + [m for m in user_map if m not in merged]
        # 3. If inline/campaign overrides are provided, merge/override as highest priority
        if inline_overrides:
            if merge_mode == 'override':
                # 3.1 Inline overrides completely override all others
                merged = list(inline_overrides)
            else:
                # 3.2 Merge: add inline entries not already present
                merged = merged + [m for m in inline_overrides if m not in merged]
        # No up-front validation; malformed entries are handled at use time
        return merged
    
    def get_field_values(self, packet: Packet, field_name: str) -> List[Any]:
        """
        Get predefined fuzz values for a field, supporting advanced override/merge logic.
        
        Behavior controlled by INCLUDE_DEFAULT_VALUES constant:
        - False (default): Only use values from FuzzFields and campaign config
        - True: Include default values from imported files as fallback
        """
        # 1. Inline/campaign config (with mode/override support)
        if hasattr(packet, 'get_field_fuzz_config'):
            field_config = packet.get_field_fuzz_config(field_name)
            if field_config and hasattr(field_config, 'default_values'):
                mode = getattr(field_config, 'mode', 'override')
                if mode == 'merge':
                    # Merge with advanced mapping and optionally default
                    field_type, properties = self._extract_field_info(packet, field_name)
                    packet_type = type(packet).__name__
                    key = f"{packet_type}.{field_name}"
                    
                    # Check for advanced dictionary override
                    adv_values = []
                    if key in FIELD_ADVANCED_DICTIONARIES:
                        adv_config = FIELD_ADVANCED_DICTIONARIES[key]
                        if isinstance(adv_config, dict) and 'dictionaries' in adv_config:
                            # Load dictionary entries if this is a dictionary reference
                            dict_entries = self.get_dictionary_entries(adv_config['dictionaries'])
                            adv_values = [entry.decode('utf-8', errors='ignore') for entry in dict_entries]
                    
                    combined_values = list(field_config.default_values)
                    if adv_values:
                        combined_values.extend(adv_values)
                    
                    # Only include default values if INCLUDE_DEFAULT_VALUES is True
                    if INCLUDE_DEFAULT_VALUES:
                        default_values = self.field_values.get(f"{type(packet).__name__}.{field_name}", [])
                        if default_values:
                            combined_values.extend(default_values)
                    
                    # Remove duplicates while preserving order
                    return list(dict.fromkeys(combined_values))
                else:
                    # Override mode: only use field config values
                    return field_config.default_values
        
        # 2. Advanced mapping (with mode/override support)
        field_type, properties = self._extract_field_info(packet, field_name)
        packet_type = type(packet).__name__
        key = f"{packet_type}.{field_name}"
        
        # Check for advanced dictionary override
        if key in FIELD_ADVANCED_DICTIONARIES:
            adv_config = FIELD_ADVANCED_DICTIONARIES[key]
            if isinstance(adv_config, dict) and 'dictionaries' in adv_config:
                # Load dictionary entries if this is a dictionary reference
                dict_entries = self.get_dictionary_entries(adv_config['dictionaries'])
                adv_values = [entry.decode('utf-8', errors='ignore') for entry in dict_entries]
                if adv_values:
                    return adv_values
        
        # 3. Default values (only if INCLUDE_DEFAULT_VALUES is True)
        if INCLUDE_DEFAULT_VALUES:
            return self.field_values.get(f"{type(packet).__name__}.{field_name}", [])
        
        # 4. Return empty list if no values found and defaults are disabled
        return []
    
    def get_field_weight(self, packet: Packet, field_name: str) -> float:
        """
        Resolve the fuzzing weight for a given field, supporting advanced combining via mode.

        Priority order:
        1. Embedded/inline field config (campaign or packet-level override):
           - If the packet has a field config with a 'weight' attribute, return it immediately.
        2. Advanced mapping (campaign/global/user override):
           - Extract field type and properties.
           - Search FIELD_ADVANCED_WEIGHTS for matching entries (supports merge/override, campaign/user/global config).
           - If matches are found, combine according to mode (override, sum, average, max, min).
        3. Name-based weight:
           - Check FIELD_NAME_WEIGHTS for a key like 'TCP.dport'.
           - If found, return the mapped weight.
        4. Type-based weight:
           - Check TYPE_FIELD_WEIGHTS for the field type (e.g., 'ShortField').
           - If found, return the mapped weight.
        5. Default:
           - If none of the above apply, return 0.5 (default weight).
        """
        # 1. Embedded/inline config (highest priority: campaign/packet-level override)
        if hasattr(packet, 'get_field_fuzz_config'):
            field_config = packet.get_field_fuzz_config(field_name)
            if field_config and hasattr(field_config, 'fuzz_weight'):
                # Inline/campaign override present
                return field_config.fuzz_weight
        # 2. Advanced mapping (campaign/global/user override)
        packet_type = type(packet).__name__
        key = f"{packet_type}.{field_name}"
        field_type, properties = self._extract_field_info(packet, field_name)
        # Use default combining mode for weights unless a per-entry mode is specified
        global_mode = "override"
        adv_result = self._resolve_advanced_weight(
            FIELD_ADVANCED_WEIGHTS,
            field_name=key,
            field_type=field_type,
            properties=properties,
            global_mode=global_mode
        )
        if adv_result is not None:
            # Advanced mapping match (campaign/global/user config)
            return adv_result
        # 3. Name-based weight (e.g., 'TCP.dport')
        if key in FIELD_NAME_WEIGHTS:
            return FIELD_NAME_WEIGHTS[key]
        # 4. Type-based weight (e.g., 'ShortField')
        if field_type in FIELD_TYPE_WEIGHTS:
            return FIELD_TYPE_WEIGHTS[field_type]
        # 5. Default fallback
        return 0.5
    
    def get_field_dictionaries(self, packet: Packet, field_name: str) -> List[str]:
        """
        Get dictionary paths for a specific field, following priority hierarchy.
        Uses advanced mapping logic.
        Respects dictionary_override at both inline/campaign and user config levels.
        Merges all sources by default if no override is set.
        """
        packet_type = type(packet).__name__
        key = f"{packet_type}.{field_name}"
        dictionary_paths = []
        # 1. Inline/campaign (FuzzField/field_fuzz) config
        inline_override = False
        if hasattr(packet, 'get_field_fuzz_config'):
            field_config = packet.get_field_fuzz_config(field_name)
            if field_config:
                # Check for dictionary_override attribute
                if hasattr(field_config, 'dictionary_override') and field_config.dictionary_override:
                    inline_override = True
                    dictionary_paths = list(field_config.dictionary) if hasattr(field_config, 'dictionary') else []
                elif hasattr(field_config, 'dictionary') and field_config.dictionary:
                    dictionary_paths.extend(field_config.dictionary)
        # 2. User config (advanced mapping)
        field_type_str, properties_dict = self._extract_field_info(packet, field_name)
        # Check for advanced dictionary configuration
        adv_dicts = []
        if key in FIELD_ADVANCED_DICTIONARIES:
            adv_config = FIELD_ADVANCED_DICTIONARIES[key]
            if isinstance(adv_config, dict) and 'dictionaries' in adv_config:
                adv_dicts = adv_config['dictionaries']
                # Check if this is an override
                if adv_config.get('override', False):
                    inline_override = True
                    dictionary_paths = list(adv_dicts)
        # If inline/campaign override, use only those dictionaries
        if inline_override:
            return [self._resolve_path(path) for path in dictionary_paths]
        # If advanced mapping returns any, merge with inline and default
        merged_paths = set(dictionary_paths)
        if adv_dicts:
            merged_paths.update(adv_dicts)
        # Type-based
        if field_type_str and field_type_str in FIELD_TYPE_DICTIONARIES:
            for d in FIELD_TYPE_DICTIONARIES[field_type_str]:
                merged_paths.update(DictionaryManager.expand_macro(d))
        # Name-based
        if key in FIELD_NAME_DICTIONARIES:
            for d in FIELD_NAME_DICTIONARIES[key]:
                merged_paths.update(DictionaryManager.expand_macro(d))
        # Convert to absolute paths and return
        return [self._resolve_path(path) for path in merged_paths]
    
    def get_packet_dictionaries(self, packet: Packet) -> List[str]:
        """
        Get dictionary paths for packet-level fuzzing.
        
        Args:
            packet: Scapy packet instance
            
        Returns:
            List of dictionary file paths
        """
        # Check packet embedded configuration
        if hasattr(packet, 'get_fuzz_config'):
            packet_config = packet.get_fuzz_config()
            if packet_config and packet_config.dictionary:
                return [self._resolve_path(path) for path in packet_config.dictionary]
        
        return []
    
    def get_dictionary_entries(self, dictionary_paths: List[str]) -> List[bytes]:
        """
        Load and combine dictionary entries from multiple files.
        Logs warnings and errors for missing or failed dictionary loads.
        
        Args:
            dictionary_paths: List of dictionary file paths
            
        Returns:
            Combined list of dictionary entries
        """
        if not dictionary_paths:
            return []
        combined_entries = []
        for dict_path in dictionary_paths:
            try:
                entries = self._load_dictionary_file(dict_path)
                combined_entries.extend(entries)
            except FileNotFoundError as e:
                logger.warning(f"Dictionary file not found: {dict_path} ({e})")
            except Exception as e:
                logger.error(f"Error loading dictionary entries from {dict_path}: {e}")
        # Remove duplicates while preserving order
        unique_entries = list(dict.fromkeys(combined_entries))
        return unique_entries
    
    def _load_dictionary_file(self, dict_path: str) -> List[bytes]:
        """Load entries from a single dictionary file"""
        try:
            if not Path(dict_path).exists():
                return []
            with open(dict_path, 'rb') as f:
                entries = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(b'#'):  # Skip empty lines and comments
                        entries.append(line)
                return entries
        except (IOError, OSError) as e:
            logger.error(f"Error loading dictionary file {dict_path}: {e}")
            return []
