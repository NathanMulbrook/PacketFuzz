#!/usr/bin/env python3
"""Dictionary Management for PacketFuzzing."""

import importlib.util
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .default_mappings import MACROS

logger = logging.getLogger(__name__)


class DictionaryManager:
    """Manages dictionary data access and advanced resolution logic for packet fuzzing."""
    
    def __init__(self, dictionary_path: Optional[str] = None, 
                 fuzzdb_path: Optional[str] = None,
                 default_dictionary_package: str = "general",
                 max_dictionary_size: int = 1000000):
        """
        Initialize the DictionaryManager.
        
        Optional custom dictionary path, FuzzDB installation path, default package name,
        and maximum dictionary size can be specified during initialization.
        """
        self.max_dictionary_size = max_dictionary_size
        self.default_dictionary_package = default_dictionary_package
        self._path_cache = {}
        self.dictionary_path = dictionary_path
        self.fuzzdb_path = fuzzdb_path or self._find_fuzzdb_path()
    
    def __str__(self) -> str:
        return f"DictionaryManager(fuzzdb={bool(self.fuzzdb_path)})"
    
    def __repr__(self) -> str:
        return f"DictionaryManager(fuzzdb_path='{self.fuzzdb_path}')"
    
    def _find_fuzzdb_path(self) -> Optional[str]:
        paths = [Path("fuzzdb"), Path("../fuzzdb"), Path("/usr/share/fuzzdb"), 
                 Path("/opt/fuzzdb"), Path.home() / "fuzzdb"]
        for path in paths:
            if path.is_dir():
                return str(path)
        return None
    
    def _resolve_path(self, path: str) -> str:
        p = Path(path)
        if p.is_absolute():
            return str(p)
        if path.startswith("fuzzdb/") and self.fuzzdb_path:
            return str(Path(self.fuzzdb_path) / path[7:])
        
        current = Path(__file__).parent
        while current != current.parent:
            fuzzdb_path = current / "fuzzdb"
            if fuzzdb_path.exists():
                return str(fuzzdb_path / path)
            current = current.parent
        return str(Path(__file__).parent / path)
    
    @staticmethod
    def expand_macro(entry: str) -> List[str]:
        """
        Expand macro references (e.g., '@string') to their dictionary lists.
        
        Returns the expanded list of dictionary entries, or a single-item list 
        containing the original entry if it's not a macro reference.
        """
        if entry.startswith("@"):
            return MACROS.get(entry[1:], [])
        return [entry]
    
    def _match_criteria(self, match: dict, field_name: str, field_type: str, properties: dict) -> bool:
        length = properties.get("length")
        context = properties.get("context")
        return (
            ("name" not in match or match["name"] == field_name) and
            ("type" not in match or match["type"] == field_type) and
            ("length" not in match or (length is not None and str(length) == str(match["length"]).replace('>', ''))) and
            ("context" not in match or match["context"] == context)
        )
    
    def _resolve_advanced_dictionary(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "merge") -> list:
        """
        Resolve advanced dictionary mappings for a field with merge/override logic.
        
        Searches through mapping entries to find matches based on field name, type,
        and properties. Combines results using merge or override mode as specified.
        """
        matches = []
        modes = []
        
        for adv in mapping_list:
            match = adv.get("match", {})
            if self._match_criteria(match, field_name, field_type, properties) and "dictionaries" in adv:
                expanded = []
                for d in adv["dictionaries"]:
                    expanded.extend(DictionaryManager.expand_macro(d))
                matches.append(expanded)
                modes.append(adv.get("mode"))
        
        if not matches:
            return []
            
        mode = next((m for m in modes if m), global_mode)
        if mode == "merge":
            return list(dict.fromkeys([v for sublist in matches for v in sublist]))
        return matches[-1]

    def _resolve_advanced_weight(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "override") -> Optional[float]:
        """
        Resolve advanced weight mappings for a field with mathematical combinations.
        
        Supports sum, average, max, min, and override modes for combining multiple
        weight matches. Returns None if no matches are found.
        """
        matches = []
        modes = []
        
        for adv in mapping_list:
            match = adv.get("match", {})
            if self._match_criteria(match, field_name, field_type, properties) and "weight" in adv:
                matches.append(float(adv["weight"]))
                modes.append(adv.get("mode"))
        
        if not matches:
            return None
            
        mode = next((m for m in modes if m), global_mode)
        weight_ops = {"sum": sum, "average": lambda x: sum(x) / len(x), "max": max, "min": min}
        return weight_ops.get(mode, lambda x: x[-1])(matches)

    def _resolve_advanced_values(self, mapping_list: list, field_name: str, field_type: str, properties: dict, global_mode: str = "override") -> list:
        """
        Resolve advanced value mappings for a field with merge/override logic.
        
        Finds matching value entries and combines them using merge (flatten and deduplicate)
        or override (last match wins) mode.
        """
        matches = []
        modes = []
        
        for adv in mapping_list:
            match = adv.get("match", {})
            if self._match_criteria(match, field_name, field_type, properties) and "values" in adv:
                matches.append(adv["values"])
                modes.append(adv.get("mode"))
        
        if not matches:
            return []
            
        mode = next((m for m in modes if m), global_mode)
        if mode == "merge":
            return list(dict.fromkeys([v for sublist in matches for v in sublist]))
        return matches[-1]

    def get_merged_field_mapping(self, default_mapping: list, user_mapping_file: Optional[str] = None, 
                                 inline_overrides: Optional[list] = None, merge_mode: Optional[str] = None,
                                 mode: str = 'dictionary') -> list:
        """
        Load and merge advanced field mappings from multiple sources.
        
        Combines default mappings with optional user mapping files (.json or .py) 
        and inline overrides. Uses merge mode for dictionaries and override mode 
        for weights/values by default.
        """
        if merge_mode is None:
            merge_mode = 'merge' if mode == 'dictionary' else 'override'

        def load_mapping_file(path: str) -> Union[Dict[str, Any], List[Any]]:
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Mapping file not found: {path}")
            if path.endswith('.json'):
                with open(path, 'r') as f:
                    return json.load(f)
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
        
        if user_mapping_file:
            user_map = load_mapping_file(user_mapping_file)
            if isinstance(user_map, dict):
                user_map = list(user_map.values()) if user_map else []
            merged = self._apply_merge_mode(merged, user_map, merge_mode)
            
        if inline_overrides:
            merged = self._apply_merge_mode(merged, inline_overrides, merge_mode)
            
        return merged
    
    def _apply_merge_mode(self, current: list, new_data: list, merge_mode: str) -> list:
        if merge_mode == 'override':
            return list(new_data)
        return current + [m for m in new_data if m not in current]
    
    def get_packet_dictionaries(self, packet) -> List[str]:
        """
        Get dictionary paths for packet-level fuzzing.
        
        Extracts dictionary configuration from the packet's fuzz_config and 
        resolves all paths to absolute file paths.
        """
        if hasattr(packet, 'get_fuzz_config'):
            packet_config = packet.get_fuzz_config()
            if packet_config and packet_config.dictionary:
                return [self._resolve_path(path) for path in packet_config.dictionary]
        return []
    
    def get_dictionary_entries(self, dictionary_paths: List[str]) -> List[bytes]:
        """
        Load and combine dictionary entries from multiple files.
        
        Reads all specified dictionary files, combines their entries, and 
        removes duplicates while preserving order. Skips comments and empty lines.
        """
        if not dictionary_paths:
            logger.info("No dictionary paths provided for field.")
            return []
        
        combined_entries = []
        for dict_path in dictionary_paths:
            entries = self._load_dictionary_file(dict_path)
            combined_entries.extend(entries)
        return list(dict.fromkeys(combined_entries))
    
    def _load_dictionary_file(self, dict_path: str) -> List[bytes]:
        if not Path(dict_path).exists():
            logger.warning(f"Dictionary file not found: {dict_path}")
            return []
        with open(dict_path, 'rb') as f:
            entries = []
            for line in f:
                line = line.strip()
                if line and not line.startswith(b'#'):
                    entries.append(line)
            return entries

