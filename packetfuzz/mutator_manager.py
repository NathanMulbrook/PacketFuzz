"""
Mutator Manager for PacketFuzzer

Manages mutator selection and orchestrates fuzzing campaigns.
Delegates all actual mutation logic to specialized mutators in the mutators/ directory.
"""

# Standard library imports
from __future__ import annotations
import copy
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path

# Third-party imports
from scapy.fields import Field, BitField, FlagsField, EnumField, StrField, IntField, ByteField, ShortField, IntEnumField
from scapy.packet import Packet, NoPayload

# Local imports
from .dictionary_manager import DictionaryManager
from .packet_extensions import install_packet_extensions
from .mutator_manager_data import MutatorManagerData, FuzzConfig, FuzzMode, FieldMetadata
from .mutators import MutatorRegistry

# Ensure mutators are registered by importing the mutators package
from . import mutators

# Default mappings import - CRITICAL: Must succeed or fail fast
from .default_mappings import LAYER_WEIGHT_SCALING as DEFAULT_LAYER_SCALING

# Import default directories - use constant directly to avoid circular imports
DEFAULT_LOG_DIR = "artifacts/logs"
from .utils.packet_report import write_debug_packet_log


logger = logging.getLogger(__name__)

# Verbosity levels: 0=quiet, 1=normal, 2=verbose, 3=debug
VERBOSITY_LEVEL = 1  # Default; can be set by campaign or CLI

# Removed unused FuzzField import - was not being used anywhere in the code

# Constants
DEFAULT_MAX_OUTPUT_SIZE = 1024
DEFAULT_MAX_MUTATIONS = 1000
DEFAULT_FUZZ_WEIGHT = 0.7
DEFAULT_MUTATOR_PREFERENCE = {"libfuzzer": 1.0}
CRITICAL_FIELDS = {'ihl', 'len', 'chksum', 'dataofs', 'sport', 'dport', 'seq', 'ack', 'flags', 'window', 'src', 'dst'}



class MutatorManager:
    """
    Manages mutator selection and orchestrates fuzzing operations.
    
    Delegates all mutation logic to specialized mutators in the mutators/ directory.
    Handles field discovery, weight calculation, and mutation orchestration.
    """
    
    # Critical fields to track for debugging
    
    # =========================
    # Initialization & Configuration
    # =========================
    def __init__(self, config: Optional[FuzzConfig] = None):
        """Initialize MutatorManager with fuzzing configuration."""
        self.fuzz_config = config or FuzzConfig()
        
        # Track which fields are fuzzed in the current iteration
        self.current_fuzzed_fields: List[str] = []
        # Track fuzzed fields metadata for each packet in a batch
        self.fuzzed_fields_per_packet: List[Dict[str, Dict[str, Any]]] = []
        
        # Initialize packet extensions (monkey patching)
        install_packet_extensions()

        #Initialize dictionary manager
        if FuzzConfig.global_dict_config_path:
            self.set_global_dictionary_config(FuzzConfig.global_dict_config_path)
        else:
            self.dictionary_manager = DictionaryManager()

        # Initialize MutatorManagerData
        self.data = MutatorManagerData(self.fuzz_config)
        self.data.preprocess_packets(self.dictionary_manager)
        
        # Initialize mutator instances dictionary with available mutators
        self.mutators: Dict[str, Any] = {}
        for mutator_name in MutatorRegistry.get_available_mutators():
            self.mutators[mutator_name] = None
        if self.fuzz_config.global_dict_config_path:
            config_path = Path(self.fuzz_config.global_dict_config_path)
            user_config_file = str(config_path) if config_path.exists() else None

    def get_field_mutation_failures(self) -> Dict[str, Dict[Tuple[str, str], int]]:
        """Get field mutation failure counts for all fields"""
        all_failures = {}
        for packet_data in self.data.packet_data:
            for field_key in packet_data.fields:
                if field_key not in all_failures:
                    all_failures[field_key] = self.data.get_field_mutation_failures(field_key)
        return all_failures

    def get_mutator_type(self, mutator_obj: Any) -> str:
        """Return the registered mutator name for field tracking."""
        if mutator_obj is None:
            return "unknown"

        # Check if the mutator class is a known BaseMutator subclass
        for mutator_name in MutatorRegistry.get_available_mutators():
            mutator_class = MutatorRegistry.get_mutator_class(mutator_name)
            if mutator_class and isinstance(mutator_obj, mutator_class):
                return mutator_name
        
        # Fallback to class name normalization if not found in registry
        cls = type(mutator_obj)
        name = getattr(cls, "__name__", str(cls))
        name = name.lower()
        # Remove common suffixes like 'mutator' or 'fuzzer' for normalization
        for suffix in ("mutator", "fuzzer"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return name.strip('_')

    
    def set_global_dictionary_config(self, config_path: str) -> None:
        """Load and set global dictionary configuration from file"""
        config_path_obj = Path(config_path)
        user_config_file = str(config_path_obj) if config_path_obj.exists() else None
        if not config_path_obj.exists():
            logger.warning(f"Global dictionary config file not found: {config_path}")
        self.dictionary_manager = DictionaryManager(user_config_file)

    # =========================
    # Public API (Main Entry Points)
    # =========================
    def fuzz_packet(self) -> MutatorManagerData:
        """
        Fuzz a complete packet
        
        Args:
            packet: The Scapy packet to fuzz
            iterations: Number of fuzzed variants to generate
            
        Returns:
            List of fuzzed packet variants
        """
        # Field-level fuzzing: mutate individual fields in the packet
        if self.fuzz_config.mode == FuzzMode.FIELD_LEVEL:
            return self.fuzz_fields()
        # Packet-level fuzzing: mutate the entire packet as a byte sequence
        elif self.fuzz_config.mode == FuzzMode.PACKET_LEVEL:
            return self._fuzz_packet_level()
        # Both field and packet-level fuzzing: start with field-level for now
        elif self.fuzz_config.mode == FuzzMode.BOTH:
            return self.fuzz_fields()  # TODO: implement proper split between field and packet level
        return self.data
    
    def fuzz_fields(self) -> MutatorManagerData:
        """
        Fuzz fields in a packet, optionally targeting a specific field.
        Args:
            packet: The Scapy packet to fuzz.
            iterations: Number of fuzzed packets to generate.
            field_name: If provided, only fuzz this field.
            merged_field_mapping: The merged advanced field mapping to use (from campaign).
        Returns:
            List of fuzzed packets.
        """
        # Handle edge case where iterations is 0
        if (self.data.fuzz_config.iterations is None) or (self.data.fuzz_config.iterations <= 0):
            if VERBOSITY_LEVEL >= 1:
                logger.info(f"[FUZZ] No iterations requested (iterations={self.data.fuzz_config.iterations})")
            return self.data
            
        # Debug logging only in verbose mode
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            log_dir = Path(DEFAULT_LOG_DIR)
            log_dir.mkdir(parents=True, exist_ok=True)
            write_debug_packet_log(self.data.original_packets, file_path=str(log_dir / "fuzz_fields_input_report.txt"), title="Fuzz Fields Input")

        # Diagnostic logging for fuzzing process
        if VERBOSITY_LEVEL >= 2:
            available_fieldtypes = self.data.get_all_fieldtypes()
            logger.info(f"[FUZZ] Starting field fuzzing: {self.data.fuzz_config.iterations} iterations, {len(available_fieldtypes)} field types available")
            if available_fieldtypes:
                logger.debug(f"[FUZZ] Available field types: {', '.join(available_fieldtypes)}")
        
        # Step 2: Initialize tracking for all packets
        
        # Step 3: Batch fuzzing - Collect all field/layer combinations across all packets
        # Since all packets are deep copies of the same original, we can use the first packet as template
   
        for field_type in self.data.get_all_fieldtypes():
            self._fuzz_field_in_layer(field_type)
        
        # Diagnostic logging for fuzzing results
        if VERBOSITY_LEVEL >= 2:
            fuzzed_count = len(self.data.fuzzed_packets) if self.data.fuzzed_packets else 0
            logger.info(f"[FUZZ] Field fuzzing complete: generated {fuzzed_count} fuzzed packets")
        
        # Write debug report of all fuzzed packets (only in debug mode)
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            #TODO update reporting
            log_dir = Path(DEFAULT_LOG_DIR)
            log_dir.mkdir(parents=True, exist_ok=True)
            write_debug_packet_log(self.data.fuzzed_packets, file_path=str(log_dir / "fuzz_fields_output_report.txt"), title="Fuzz Fields Output")
        
        # Return the fuzzed packets from the data object
        return self.data

    # =========================
    # Field/Packet Fuzzing Internals
    # =========================
    def _fuzz_field_in_layer(self, field_type: str) -> List[int]:
        """
        Fuzz a specific field across multiple layers (batch processing) with dictionary and mutation support.
        
        Args:
            field_type: Type of field to fuzz
            
        Returns:
            List of indexes (0-based) of layers that were NOT fuzzed (due to skipping or failure)
        """
        # Selection is now handled at the batch level, so proceed with fuzzing
        logger.debug(f"Fuzzing field {field_type} ")

        # Clear mutator instances to ensure fresh state for each field type
        for each in self.mutators:
            self.mutators[each] = None

        fields_to_fuzz = self.data.get_all_fields_of_type(field_type)

        # Iterate through all fields of this type
        failed_indices: List[int] = []
        for field in fields_to_fuzz:
            # Within this block we are fuzzing a single field
            # Handle default values for the field if present
            if field.default_values:
                pick_rng = self.fuzz_config.rng or random
                pick = pick_rng.choice(field.default_values)
                self.data.validate_and_assign(field, pick)
                # Not recording this as a mutation; it's a deterministic assignment
            else:
                dictionary_entries = self.dictionary_manager.get_dictionary_entries(
                    getattr(field, 'dictionary_paths', []) or []
                )
                mutator_selection = self._select_mutator_for_field(field)
                if mutator_selection and mutator_selection != "skip":
                    mutator = self.get_mutator_and_initialize(mutator_selection, field, dictionary_entries)
                    failed = self._mutate_with_retries(field, mutator, dictionary_entries)
                    failed_indices.extend(failed)

        return failed_indices

    def _select_mutator_for_field(self, field: FieldMetadata) -> str:
        # Skip fields with zero weight immediately
        if field.fuzz_weight == 0.0:
            return "skip"
            
        # Use fuzz_weight as probability to CONTINUE fuzzing (higher weight = more likely to fuzz)
        if random.random() >= field.fuzz_weight:
            return "skip"

        # Select mutator using weighted selection
        if field.mutator_weights:
            mutators = list(field.mutator_weights.keys())
            weights = list(field.mutator_weights.values())
            mutator_selection = random.choices(mutators, weights=weights, k=1)[0]
        else:
            # Fallback to default when no weights configured
            mutator_selection = "libfuzzer"
        
        # Apply legacy weight overrides (deprecated but maintained for compatibility)
        if random.random() < field.dictionary_only_weight:
            mutator_selection = "dictionary_only"
        if random.random() < field.scapy_fuzz_weight:
            mutator_selection = "scapy"

        return mutator_selection
    
    def get_mutator_and_initialize(self, mutator_selection: str, field_info: FieldMetadata, dictionary_entries: List[bytes]) -> Optional[Any]:
        """
        Get a mutator instance by name and initialize it with field information.
        
        Args:
            mutator_selection: Name of the mutator ("libfuzzer", "scapy", "dictionary_only")
            field_info: Field metadata for mutator initialization
            dictionary_entries: Dictionary data for enhanced mutations
            
        Returns:
            Initialized mutator instance or None if not available
        """
        mutator = None
        mutator_class = MutatorRegistry.get_mutator_class(mutator_selection)
        if mutator_class:
            if self.mutators[mutator_selection] is None:
                self.mutators[mutator_selection] = mutator_class()
            mutator = self.mutators[mutator_selection]
        else:
            logger.debug(f"No valid mutator found for selection: {mutator_selection}")

        if mutator and not mutator.initialized:
            mutator.initialize(field_info, dictionary_entries)

        return mutator

    def _apply_field_type_compatibility(self, field_info: FieldMetadata, mutated_value: Any) -> Any:
        """
        Apply field type compatibility transformations to mutator output.
        
        This method handles cases where specific field types expect different data formats
        than what mutators naturally produce. For example, Unknown_Headers expects 
        dictionary format while mutators typically generate strings.
        
        Args:
            field_info: Field metadata containing field name and type information
            mutated_value: Raw value from mutator (string, int, bytes, etc.)
            
        Returns:
            Compatible value in the format expected by the field type
        """
        # Handle HTTP header fields that expect dictionary format
        field_name = getattr(field_info, 'field_name', 'Unknown')
        field_type = getattr(field_info, 'field_type', None)
        
        if (field_type and '_HTTPHeaderField' in field_type and 
            field_name == 'Unknown_Headers'):
            # Unknown_Headers expects dictionary format for multiple custom headers
            # Convert any input to dictionary format
            if isinstance(mutated_value, dict):
                # Already in correct format
                return mutated_value
            elif isinstance(mutated_value, (str, bytes)):
                # Convert string/bytes to dictionary format
                s = mutated_value.decode('utf-8', errors='ignore') if isinstance(mutated_value, bytes) else str(mutated_value)
                if ':' in s:
                    parts = s.split(':', 1)
                    header_name = parts[0].strip()
                    header_value = parts[1].strip() if len(parts) > 1 else ''
                    return {header_name: header_value}
                else:
                    # No colon found, create a custom header
                    return {f"X-Custom-{field_name}": s}
            else:
                # For other types (int, etc.), convert to string first then to dict
                s = str(mutated_value)
                return {f"X-Custom-{field_name}": s}
        
        # For all other fields, return the original value unchanged
        return mutated_value

    def _mutate_with_retries(self, field_info: FieldMetadata, mutator, dictionary_entries: List ) -> List[int]:
        """
        Attempt to mutate a field value across multiple layers with retry logic for robustness.
        
        Uses the configured mutator selection strategy to generate new values for the specified field
        across all provided layers. If mutation fails (due to validation errors, serialization issues, etc.), 
        retries up to max_attempts times before reverting to the original value and failing gracefully.
        
        Args:
            field_info: FieldInfo object containing field metadata (type, constraints, etc.)
            layers: List of Scapy packet layers containing the field to mutate
            field_desc: Scapy field descriptor object for weight checking
            fname: Name of the field to mutate
            current_value: Current/original value of the field (may be None for FuzzFields)
            dictionaries: List of dictionary entries (bytes) to use for mutation
            fuzzfield_config: Configuration extracted from FuzzField (mutator preferences, etc.)
            
        Returns:
            List of indexes (0-based) of layers that were NOT fuzzed (due to failure or weight skip)
            
        Side Effects:
            - Modifies the field value on layer objects if successful
            - Records mutation failures in self.field_mutation_failures for reporting
            - Reverts to original values if all attempts fail
            - Logs warnings for persistent failures
            - Initializes mutator corpus if supported by the selected mutator
            - Applies per-layer weight checking for proper layer weight scaling
        """
        
        # Try a few time to mutate a field
        attempts = 0
        last_err = None
        success = False

        while attempts < 3 and not success:
            attempts += 1

            try:
                #Mutate the field
                mutated_value = mutator.mutate_field(field_info, dictionaries=dictionary_entries, rng=self.fuzz_config.rng, layer=None)
                mutator_type = self.get_mutator_type(mutator)
                
                # Apply field type compatibility layer - convert mutator output to expected format
                # This handles cases where specific field types (like Unknown_Headers) expect different
                # data formats than what mutators naturally produce, eliminating validation failures
                # and retry overhead that previously caused significant performance degradation
                compatible_value = self._apply_field_type_compatibility(field_info, mutated_value)
                
                success = self.data.validate_and_assign(field_info, value=compatible_value)
                last_err = None  # Clear error on success
            except Exception as e:
                last_err = str(e)
                success = False

        # If all attempts failed
        if not success:
            logger.warning(f"Field mutation failed after {attempts} attempts: {field_info.field_key}: {last_err}")
            
            # Record failure using centralized tracking
            self.data.record_field_mutation(field_info.field_key, field_info.packet_index, False, mutator_type if 'mutator_type' in locals() else "unknown")
            
            # Revert to original value through the data class
            # Get the original value and revert
            original_value = field_info.current_value
            if original_value is not None:
                # Try to revert to original value
                revert_success = self.data.validate_and_assign(field_info, original_value)
                if field_info.field_name in CRITICAL_FIELDS:
                    if revert_success:
                        logger.debug(f"Reverted {field_info.field_key} to {original_value} (mutation fallback)")
                    else:
                        logger.debug(f"Failed to revert {field_info.field_key} to {original_value} (mutation fallback)")
            else:
                if field_info.field_name in CRITICAL_FIELDS:
                    logger.debug(f"No original value to revert for {field_info.field_key} (mutation fallback)")
        else:
            # Record successful mutation using centralized tracking
            self.data.record_field_mutation(field_info.field_key, field_info.packet_index, True, mutator_type if 'mutator_type' in locals() else "unknown")
            
            if field_info.field_name in CRITICAL_FIELDS:
                logger.debug(f"Mutate with retries result for {field_info.field_key}: {field_info.current_value}")
                logger.debug(f"Mutate with retries result for {field_info.field_key}: {field_info.current_value}")

        # Return list of failed indices (empty if success, [0] if failed)
        return [] if success else [0]


    def _fuzz_packet_level(self) -> MutatorManagerData:
        """
        Fuzz the packet(s) at the byte level using the new consolidated API and MutatorManagerData.
        Returns MutatorManagerData with mutated packets in packet_list.
        """
        # Select mutator using preference system with weighted selection
        mutator = None
        prefs = self.fuzz_config.mutator_preference or DEFAULT_MUTATOR_PREFERENCE
        
        # Ensure prefs is in dict format 
        if isinstance(prefs, list):
            # Convert list to dict with equal weights
            prefs = {name: 1.0 for name in prefs}
        elif not isinstance(prefs, dict):
            prefs = DEFAULT_MUTATOR_PREFERENCE
        
        # Use weighted selection
        mutator_names = list(prefs.keys())
        weights = list(prefs.values())
        selected_mutator_name = random.choices(mutator_names, weights=weights, k=1)[0]
        
        # Initialize and get the selected mutator
        mutator_class = MutatorRegistry.get_mutator_class(selected_mutator_name)
        if mutator_class:
            if self.mutators[selected_mutator_name] is None:
                self.mutators[selected_mutator_name] = mutator_class()
            mutator = self.mutators[selected_mutator_name]
        
        # Fallback if no mutator was selected
        if mutator is None:
            for fallback_name in MutatorRegistry.get_available_mutators():
                fallback_class = MutatorRegistry.get_mutator_class(fallback_name)
                if fallback_class and self.mutators[fallback_name] is None:
                    self.mutators[fallback_name] = fallback_class()
                if self.mutators[fallback_name] is not None:
                    mutator = self.mutators[fallback_name]
                    break

        mutator_name = self.get_mutator_type(mutator)

        # Iterate over all packets in MutatorManagerData
        iters_cfg = getattr(self.fuzz_config, 'iterations', None)
        iterations = int(iters_cfg) if isinstance(iters_cfg, int) and iters_cfg > 0 else 1
        mutated_packets = []
        for packet_index, packet in enumerate(self.data.original_packets):
            # Get packet-level dictionaries using consolidated API
            dictionary_paths = self.dictionary_manager.get_packet_dictionaries(packet)
            if not dictionary_paths:
                # Collect dictionary paths from processed field metadata
                all_paths = set()
                if packet_index < len(self.data.packet_data):
                    packet_data = self.data.packet_data[packet_index]
                    for field_metadata in packet_data.fields.values():
                        if field_metadata.dictionary_paths:
                            all_paths.update(field_metadata.dictionary_paths)
                dictionary_paths = list(all_paths)
            dictionaries = self.dictionary_manager.get_dictionary_entries(dictionary_paths)

            # Perform mutations for each iteration
            from scapy.packet import Raw
            for _ in range(iterations):
                packet_bytes = bytes(packet)
                if mutator:
                    fuzzed_bytes = mutator.mutate_bytes(packet_bytes, dictionaries)
                else:
                    fuzzed_bytes = packet_bytes
                fuzzed_packet = Raw(fuzzed_bytes)
                mutated_packets.append(fuzzed_packet)

        # Update MutatorManagerData with mutated packets
        self.data.fuzzed_packets = mutated_packets
        return self.data
    

