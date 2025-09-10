#!/usr/bin/env python3
"""Dictionary Management for PacketFuzzing."""

import importlib.util
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple

from .default_mappings import MACROS

logger = logging.getLogger(__name__)

# Deduplication configuration - always use enhanced with case sensitivity
CASE_SENSITIVE_DEDUP = True


class DictionaryManager:
    """Manages dictionary data access and advanced resolution logic for packet fuzzing."""
    
    def __init__(self, dictionary_path: Optional[str] = None, 
                 fuzzdb_path: Optional[str] = None,
                 default_dictionary_package: str = "general",
                 max_dictionary_size: int = 1000000):
        """
        Initialize the DictionaryManager.
        
        Args:
            dictionary_path: Optional custom dictionary path
            fuzzdb_path: Optional FuzzDB installation path  
            default_dictionary_package: Default package name
            max_dictionary_size: Maximum dictionary size
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
    def expand_macro(entry: str, visited: Optional[set] = None) -> List[str]:
        """
        Recursively expand macro references (e.g., '@string') to their dictionary lists.
        
        Returns the expanded list of dictionary file paths, or a single-item list 
        containing the original entry if it's not a macro reference.
        Handles nested macro references and prevents circular dependencies.
        
        Args:
            entry: The entry to expand (could be a macro reference or file path)
            visited: Set of visited macros to prevent circular references (internal use)
            
        Returns:
            List of fully resolved file paths
        """
        if visited is None:
            visited = set()
            
        if not entry.startswith("@"):
            return [entry]
        
        macro_name = entry[1:]
        if macro_name in visited:
            logger.warning(f"Circular macro reference detected: {macro_name}")
            return []
        
        if macro_name not in MACROS:
            logger.warning(f"Unknown macro: @{macro_name}")
            return []
        
        visited.add(macro_name)
        expanded_paths = []
        
        for macro_entry in MACROS[macro_name]:
            sub_expanded = DictionaryManager.expand_macro(macro_entry, visited.copy())
            expanded_paths.extend(sub_expanded)
        
        return expanded_paths
    
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
        removes duplicates using enhanced case-sensitive deduplication while preserving order.
        Skips comments and empty lines.
        
        Args:
            dictionary_paths: List of dictionary file paths to load
            
        Returns:
            List of deduplicated dictionary entries as bytes
        """
        if not dictionary_paths:
            logger.info("No dictionary paths provided for field.")
            return []
        
        combined_entries = []
        for dict_path in dictionary_paths:
            for resolved_path in self.expand_macro(dict_path):
                combined_entries.extend(self._load_dictionary_file(resolved_path))
        
        original_count = len(combined_entries)
        combined_entries = self._enhanced_deduplicate_bytes(combined_entries)
        deduplicated_count = len(combined_entries)
        if original_count != deduplicated_count:
            logger.debug(f"Enhanced deduplication: {original_count} -> {deduplicated_count} entries "
                       f"({original_count - deduplicated_count} duplicates removed)")
        return combined_entries
    
    def _enhanced_deduplicate_bytes(self, entries: List[bytes]) -> List[bytes]:
        """
        Enhanced deduplication of byte entries with case-sensitive comparison.
        
        Removes duplicates while preserving order, with:
        - Case-sensitive comparison (preserves case differences)
        - Whitespace normalization
        - Empty entry removal
        - Proper Unicode handling
        
        Args:
            entries: List of byte entries to deduplicate
            
        Returns:
            List of deduplicated entries as bytes
        """
        if not entries:
            return []
        
        seen_normalized = set()
        deduplicated = []
        
        for entry in entries:
            if not entry or not entry.strip():
                continue  # Skip empty or whitespace-only entries
                
            try:
                entry_str = entry.decode('utf-8', errors='ignore').strip()
            except (UnicodeDecodeError, AttributeError):
                # If decoding fails, treat as bytes directly
                entry_str = str(entry).strip()
            
            if not entry_str:
                continue  # Skip entries that become empty after normalization
                
            # Use case-sensitive comparison (no .lower() transformation)
            normalized = entry_str
            
            if normalized not in seen_normalized:
                seen_normalized.add(normalized)
                if isinstance(entry, bytes):
                    deduplicated.append(entry.strip())
                else:
                    deduplicated.append(entry_str.encode('utf-8'))
        
        return deduplicated
    
    def get_dictionary_entries_with_stats(self, dictionary_paths: List[str]) -> Tuple[List[bytes], Dict[str, int]]:
        """
        Load dictionary entries and return both entries and deduplication statistics.
        
        Uses enhanced case-sensitive deduplication.
        
        Args:
            dictionary_paths: List of dictionary file paths to load
            
        Returns:
            Tuple of (deduplicated_entries, stats_dict) where stats_dict contains:
            - 'original_count': Number of entries before deduplication
            - 'final_count': Number of entries after deduplication  
            - 'duplicates_removed': Number of duplicates removed
            - 'files_processed': Number of dictionary files processed
        """
        if not dictionary_paths:
            return [], {'original_count': 0, 'final_count': 0, 'duplicates_removed': 0, 'files_processed': 0}
        
        combined_entries = []
        files_processed = 0
        
        for dict_path in dictionary_paths:
            expanded_paths = self.expand_macro(dict_path)
            for resolved_path in expanded_paths:
                entries = self._load_dictionary_file(resolved_path)
                if entries:  # Only count files that actually contributed entries
                    files_processed += 1
                combined_entries.extend(entries)
        
        original_count = len(combined_entries)
        final_entries = self._enhanced_deduplicate_bytes(combined_entries)
        final_count = len(final_entries)
        
        stats = {
            'original_count': original_count,
            'final_count': final_count,
            'duplicates_removed': original_count - final_count,
            'files_processed': files_processed
        }
        
        return final_entries, stats
    
    def _load_dictionary_file(self, dict_path: str) -> List[bytes]:
        if not Path(dict_path).exists():
            logger.warning(f"Dictionary file not found: {dict_path}")
            return []
        with open(dict_path, 'rb') as f:
            entries = []
            for line in f:
                if (stripped_line := line.strip()) and not stripped_line.startswith(b'#'):
                    entries.append(stripped_line)
            return entries

