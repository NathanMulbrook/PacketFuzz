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
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# Third-party imports
from scapy.fields import Field, BitField, FlagsField, EnumField, StrField, IntField, ByteField, ShortField, IntEnumField
from scapy.packet import Packet, NoPayload

# Local imports
from .dictionary_manager import DictionaryManager
from .packet_extensions import install_packet_extensions

# Mutator imports (with graceful fallback)
try:
    from .mutators.dictionary_only_mutator import DictionaryOnlyMutator
except Exception:
    DictionaryOnlyMutator = None  # type: ignore
try:
    from .mutators.libfuzzer_mutator import LibFuzzerMutator
except Exception:
    LibFuzzerMutator = None  # type: ignore
try:
    from .mutators.scapy_mutator import ScapyMutator
except Exception:
    ScapyMutator = None  # type: ignore

# Default mappings import
try:
    from .default_mappings import LAYER_WEIGHT_SCALING as DEFAULT_LAYER_SCALING
except Exception:
    DEFAULT_LAYER_SCALING = 0.9

# Import default directories - use constant directly to avoid circular imports
DEFAULT_LOG_DIR = "artifacts/logs"
from .utils.packet_report import write_debug_packet_log


logger = logging.getLogger(__name__)

# Verbosity levels: 0=quiet, 1=normal, 2=verbose, 3=debug
VERBOSITY_LEVEL = 1  # Default; can be set by campaign or CLI

# Import FuzzField for direct handling
try:
    from fuzzing_framework import FuzzField
except ImportError:
    FuzzField = None

# Constants
DEFAULT_MAX_OUTPUT_SIZE = 1024
DEFAULT_MAX_MUTATIONS = 1000
DEFAULT_FUZZ_WEIGHT = 0.7


# =========================
# FieldInfo (top-level)
# =========================
@dataclass
class FieldInfo:
    name: str
    layer_name: str
    kind: str
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    enum_map: Optional[dict] = None
    signed: Optional[bool] = None
    max_length: Optional[int] = None


def get_log_file_path(filename: str) -> str:
    """
    Get the full path for a log file in the logs directory.
    
    Args:
        filename: The name of the log file
        
    Returns:
        Full path to the log file in the logs directory
    """
    log_dir = Path(DEFAULT_LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    return str(log_dir / filename)


class FuzzMode(Enum):
    """Fuzzing mode selection"""
    PACKET_LEVEL = "packet"
    FIELD_LEVEL = "field"
    BOTH = "both"


@dataclass
class FuzzConfig:
    """Configuration for fuzzing operations
    mutator_preference must be a list of strings (e.g., ['libfuzzer']).
    """
    mode: FuzzMode = FuzzMode.BOTH
    max_mutations: int = DEFAULT_MAX_MUTATIONS
    use_dictionaries: bool = True
    fuzz_weight: float = DEFAULT_FUZZ_WEIGHT  # Probability of fuzzing a field
    simple_field_fuzz_weight: Optional[float] = None  # Probability of fuzzing simple fields
    fuzz_weight_scale: float = 1.0  # Global scaling factor for fuzz probabilities
    # Layer-based scaling configuration (multiplier per layer distance from innermost)
    layer_weight_scaling: Optional[float] = None  # None = use default mapping constant
    enable_layer_weight_scaling: bool = True
    mutator_preference: List[str] = field(default_factory=lambda: ["libfuzzer"])
    global_dict_config_path: Optional[str] = None  # Path to global dictionary configuration
    rng: Optional[random.Random] = None  # Optional random generator for reproducibility

    def __str__(self) -> str:
        return f"FuzzConfig(mode={self.mode.value}, max_mutations={self.max_mutations})"

    def __repr__(self) -> str:
        return (f"FuzzConfig(mode={self.mode}, max_mutations={self.max_mutations}, "
                f"use_dictionaries={self.use_dictionaries}, mutator_preference={self.mutator_preference})")


class MutatorManager:
    """
    Manages mutator selection and orchestrates fuzzing operations.
    
    Delegates all mutation logic to specialized mutators in the mutators/ directory.
    Handles field discovery, weight calculation, and mutation orchestration.
    """
    
    # Critical fields to track for debugging
    CRITICAL_FIELDS = {'ihl', 'len', 'chksum', 'dataofs', 'sport', 'dport', 'seq', 'ack', 'flags', 'window', 'src', 'dst'}
    
    # =========================
    # Initialization & Configuration
    # =========================
    def __init__(self, config: Optional[FuzzConfig] = None):
        self.config = config or FuzzConfig()
        
        # Track which fields are fuzzed in the current iteration
        self.current_fuzzed_fields: List[str] = []
        # Track fuzzed fields metadata for each packet in a batch
        self.fuzzed_fields_per_packet: List[Dict[str, Dict[str, Any]]] = []
        
        # Initialize packet extensions (monkey patching)
        install_packet_extensions()
        
        # Initialize enhanced dictionary manager
        user_config_file = None
        if self.config.global_dict_config_path:
            config_path = Path(self.config.global_dict_config_path)
            user_config_file = str(config_path) if config_path.exists() else None
        self.dictionary_manager = DictionaryManager(user_config_file)
        self.libfuzzer_mutator = None
        self.dictionary_only_mutator = None
        self.scapy_mutator = None
        # Always attempt to initialize all mutators, regardless of preference
        try:
            if LibFuzzerMutator is not None:
                self.libfuzzer_mutator = LibFuzzerMutator()
        except Exception as e:
            logger.error(f"Failed to initialize LibFuzzerMutator: {e}")
            self.libfuzzer_mutator = None
        try:
            if DictionaryOnlyMutator is not None:
                self.dictionary_only_mutator = DictionaryOnlyMutator()
        except Exception as e:
            logger.error(f"Failed to initialize DictionaryOnlyMutator: {e}")
            self.dictionary_only_mutator = None
        try:
            if ScapyMutator is not None:
                self.scapy_mutator = ScapyMutator()
        except Exception as e:
            logger.error(f"Failed to initialize ScapyMutator: {e}")
            self.scapy_mutator = None
        # Track per-field mutation failures for reporting/analysis
        self.field_mutation_failures: Dict[Tuple[str, str], int] = {}

    def __del__(self):
        """Automatic cleanup when MutatorManager is destroyed."""
        self.teardown()

    def teardown(self) -> None:
        """
        Clean up all mutator resources.
        
        This method should be called when the MutatorManager is no longer needed
        to ensure proper cleanup of mutator resources.
        """
        try:
            if self.libfuzzer_mutator:
                self.libfuzzer_mutator.teardown()
                logger.debug("LibFuzzer mutator teardown completed")
        except Exception as e:
            logger.debug(f"LibFuzzer mutator teardown failed: {e}")
        
        try:
            if self.dictionary_only_mutator:
                self.dictionary_only_mutator.teardown()
                logger.debug("Dictionary-only mutator teardown completed")
        except Exception as e:
            logger.debug(f"Dictionary-only mutator teardown failed: {e}")
        
        try:
            if self.scapy_mutator:
                self.scapy_mutator.teardown()
                logger.debug("Scapy mutator teardown completed")
        except Exception as e:
            logger.debug(f"Scapy mutator teardown failed: {e}")
        
        logger.debug("MutatorManager teardown completed")

    def get_current_fuzzed_fields(self) -> List[str]:
        """Get the list of fields that were fuzzed in the current iteration"""
        return self.current_fuzzed_fields.copy()
        
    def get_fuzzed_fields_for_packet(self, packet_index: int) -> List[str]:
        """Get the list of fields that were fuzzed for a specific packet in the last batch"""
        if 0 <= packet_index < len(self.fuzzed_fields_per_packet):
            return list(self.fuzzed_fields_per_packet[packet_index].keys())
        return []

    def get_mutator_usage_counts(self) -> Dict[str, int]:
        """Get mutator usage counts from the tracked field data"""
        counts: Dict[str, int] = {}
        for packet_data in self.fuzzed_fields_per_packet:
            for field_data in packet_data.values():
                mutator = field_data.get('mutator', 'unknown')
                counts[mutator] = counts.get(mutator, 0) + 1
        return counts

    def get_field_mutation_failures(self) -> Dict[Tuple[str, str], int]:
        """Get field mutation failure counts"""
        return self.field_mutation_failures.copy()

    def _field_value_changed(self, original_value, new_value):
        """Check if a field value actually changed from its original value."""
        # Handle None and empty string cases - be more strict about meaningful changes
        if original_value is None:
            # For None -> empty string, don't consider this a meaningful change
            if new_value in ("", b""):
                return False
            # Any other non-None value is considered a change
            return new_value is not None
        if original_value in ("", b"") and new_value in (None, "", b""):
            return False
        
        # For meaningful comparison, convert both to same type if possible
        try:
            if isinstance(original_value, bytes) and isinstance(new_value, str):
                return original_value != new_value.encode()
            elif isinstance(original_value, str) and isinstance(new_value, bytes):
                return original_value.encode() != new_value
        except:
            pass
        
        return original_value != new_value

    def _record_mutator_usage(self, mutator_obj: Any) -> str:
        """Record mutator usage and return the mutator name for field tracking"""
        try:
            name = None
            if mutator_obj is None:
                name = "none"
            else:
                cls_name = mutator_obj.__class__.__name__.lower()
                if "dictionary" in cls_name and "only" in cls_name:
                    name = "dictionary_only"
                elif "libfuzzer" in cls_name:
                    name = "libfuzzer"
                elif "scapy" in cls_name:
                    name = "scapy"
                else:
                    name = cls_name
            return name or "unknown"
        except Exception:
            return "unknown"

    
    def set_global_dictionary_config(self, config_path: str) -> None:
        """Load and set global dictionary configuration from file"""
        config_path_obj = Path(config_path)
        user_config_file = str(config_path_obj) if config_path_obj.exists() else None
        if not config_path_obj.exists():
            logger.warning(f"Global dictionary config file not found: {config_path}")
        self.dictionary_manager = DictionaryManager(user_config_file)

    def set_mutator(self, mutator: Any) -> None:
        """Set a custom mutator"""
        self.mutator = mutator

    # =========================
    # Public API (Main Entry Points)
    # =========================
    def fuzz_packet(self, packet: Packet, iterations: int = 1) -> List[Packet]:
        """
        Fuzz a complete packet
        
        Args:
            packet: The Scapy packet to fuzz
            iterations: Number of fuzzed variants to generate
            
        Returns:
            List of fuzzed packet variants
        """
        # Field-level fuzzing: mutate individual fields in the packet
        if self.config.mode == FuzzMode.FIELD_LEVEL:
            return self.fuzz_fields(packet, iterations)
        # Packet-level fuzzing: mutate the entire packet as a byte sequence
        elif self.config.mode == FuzzMode.PACKET_LEVEL:
            return self._fuzz_packet_level(packet, iterations)
        # Split iterations between field-level and packet-level fuzzing
        else:
            # Ensure at least 1 iteration for field fuzzing when iterations > 0
            field_iterations = max(1, iterations // 2) if iterations > 0 else 0
            field_variants = self.fuzz_fields(packet, field_iterations)
            packet_variants = self._fuzz_packet_level(packet, iterations - len(field_variants))
            # Combine results from both fuzzing strategies
            return field_variants + packet_variants
    
    def fuzz_fields(self, packet: Packet, iterations: int = 1, field_name: Optional[str] = None, merged_field_mapping: Optional[List[dict]] = None) -> List[Packet]:
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
        if iterations <= 0:
            return []
            
        # Debug logging only in verbose mode
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            write_debug_packet_log([packet], file_path=get_log_file_path("fuzz_fields_input_report.txt"), title="Fuzz Fields Input")
        
        # Reset the per-packet tracking
        self.fuzzed_fields_per_packet = []
        
        # Step 1: Create packet list that is deep copied
        packet_list: List[Packet] = []
        for i in range(iterations):
            fuzzed_packet = copy.deepcopy(packet)
            packet_list.append(fuzzed_packet)
        
        # Step 2: Initialize tracking for all packets
        self.fuzzed_fields_per_packet = [{} for i in range(iterations)]
        
        # Step 3: Batch fuzzing - Collect all field/layer combinations across all packets
        # Since all packets are deep copies of the same original, we can use the first packet as template
        field_batch_map: Dict[Tuple[str, str], List[Tuple[int, Any, Any]]] = {}  # (layer_class, field_name) -> [(packet_idx, layer, field_desc)]
        
        # Use first packet as template since all packets are identical copies
        template_packet = packet_list[0]
        layers = template_packet.layers()
        logger.info(f"Template packet layers: {[layer.__name__ for layer in layers]}")
        
        for layer_class in layers:
            template_layer = template_packet.getlayer(layer_class)
            logger.debug(f"Processing template layer: {layer_class.__name__}")
            if template_layer is None:
                continue
            for field_desc in template_layer.fields_desc:
                fname = field_desc.name
                logger.debug(f"Processing field: {layer_class.__name__}.{fname}")
                # Skip specific field if requested
                if field_name and fname != field_name:
                    logger.debug(f"Skipping field {layer_class.__name__}.{fname} due to field_name not matching")
                    continue
                
                # Create batch key and populate with all corresponding layers from all packets
                batch_key = (layer_class.__name__, fname)
                field_batch_map[batch_key] = []
                for packet_idx, packet in enumerate(packet_list):
                    layer = packet.getlayer(layer_class)
                    if layer is not None:
                        field_batch_map[batch_key].append((packet_idx, layer, field_desc))
        
        # Second pass: Process each unique field across all packets in batch
        # First collect all fields with their weights for selection logic
        field_candidates = []
        for (layer_class_name, fname), packet_layer_list in field_batch_map.items():
            if not packet_layer_list:
                continue
            first_packet_idx, first_layer, first_field_desc = packet_layer_list[0]
            field_candidates.append((layer_class_name, fname, packet_layer_list, first_field_desc))
        
        # Sort candidates by weight (highest first) to prioritize higher-weight fields
        def get_field_weight(field_tuple):
            layer_class_name, fname, packet_layer_list, first_field_desc = field_tuple
            first_layer = packet_layer_list[0][1]
            return self.dictionary_manager.get_field_weight(first_layer, fname)
        
        field_candidates.sort(key=get_field_weight, reverse=True)
        
        # Target number of fields to select (reasonable balance)
        min_fields = max(2, min(8, len(field_candidates) // 10))  # At least 2, at most 8, roughly 10% of available
        max_fields = min(15, len(field_candidates) // 3)  # Cap at 15 or 1/3 of available fields
        target_fields = min_fields
        
        fields_selected = 0
        for layer_class_name, fname, packet_layer_list, first_field_desc in field_candidates:
            first_layer = packet_layer_list[0][1]
            base_weight = self.dictionary_manager.get_field_weight(first_layer, fname)
            
            # Selection logic: guaranteed selection for high-priority fields, probabilistic for others
            should_select = False
            if fields_selected < min_fields:
                # Guarantee minimum field selection (but still respect zero weights)
                should_select = base_weight > 0
                logger.debug(f"Guaranteed selection for {layer_class_name}.{fname} (weight {base_weight}, selected {fields_selected}/{min_fields})")
            elif fields_selected < max_fields:
                # Probabilistic selection for additional fields beyond minimum
                rng = self.config.rng if self.config.rng else random
                random_val = rng.random()
                should_select = random_val < base_weight
                logger.debug(f"Probabilistic selection for {layer_class_name}.{fname} (weight {base_weight}, random {random_val:.3f}, selected: {should_select})")
            else:
                # Stop selecting once we hit max_fields
                logger.debug(f"Skipping {layer_class_name}.{fname} (max fields {max_fields} reached)")
                continue
            
            if not should_select:
                logger.debug(f"Skipping {layer_class_name}.{fname} (not selected)")
                continue
            
            logger.debug(f"Processing {layer_class_name}.{fname} across {len(packet_layer_list)} packets")
            
            # Extract all layers for batch processing
            layers_for_batch = [layer for _, layer, _ in packet_layer_list]
            unfuzzed_indexes = self._fuzz_field_in_layer(layers_for_batch, first_field_desc, fname, merged_field_mapping)
            
            # Update tracking for each packet based on fuzzing results
            if self.current_fuzzed_fields:
                field_identifier = f"{layer_class_name}.{fname}"
                # Get the actual mutator used (this would need to be returned from _fuzz_field_in_layer)
                for idx, (packet_idx, layer, _) in enumerate(packet_layer_list):
                    if idx not in unfuzzed_indexes:
                        # Track successful fuzzing with metadata
                        self.fuzzed_fields_per_packet[packet_idx][field_identifier] = {
                            'status': 'success',
                            'mutator': 'batch_processed',  # Enhanced with actual mutator info
                            'layer_class': layer_class_name,
                            'field_name': fname
                        }
                fields_selected += 1
        
        # Step 4: FORCE_FUZZ - Ensure at least one field is fuzzed per packet
        for packet_idx in range(iterations):
            if not self.fuzzed_fields_per_packet[packet_idx]:  # No fields fuzzed in this packet
                logger.debug(f"FORCE_FUZZ: Packet {packet_idx} has no fuzzed fields, attempting to force fuzz")
                # Try to force fuzz the first available field in all layers
                packet = packet_list[packet_idx]
                layers = packet.layers()
                for layer_class in layers:
                    layer = packet.getlayer(layer_class)
                    if layer is None:
                        continue
                    for field_desc in layer.fields_desc:
                        fname = field_desc.name
                        # Skip specific field if requested
                        if field_name and fname != field_name:
                            continue
                        # Try to force fuzz this field
                        single_layer = [layer]
                        unfuzzed_indexes = self._fuzz_field_in_layer(single_layer, field_desc, fname, merged_field_mapping, force_fuzz=True)
                        if 0 not in unfuzzed_indexes:  # Successfully fuzzed
                            field_identifier = f"{layer_class.__name__}.{fname}"
                            self.fuzzed_fields_per_packet[packet_idx][field_identifier] = {
                                'status': 'success',
                                'mutator': 'force_fuzz',
                                'layer_class': layer_class.__name__,
                                'field_name': fname
                            }
                            logger.debug(f"FORCE_FUZZ: Successfully forced fuzz of {field_identifier} in packet {packet_idx}")
                            break  # Move to next packet
                    if self.fuzzed_fields_per_packet[packet_idx]:  # Found a field to fuzz
                        break  # Move to next packet
        
        # Write debug report of all fuzzed packets (only in debug mode)
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            try:
                write_debug_packet_log(packet_list, file_path=get_log_file_path("fuzz_fields_output_report.txt"), title="Fuzz Fields Output")
            except Exception as e:
                logger.debug(f"Failed to write packet report: {e}")
                # Continue execution even if report writing fails
        
        return packet_list

    # =========================
    # Field/Packet Fuzzing Internals
    # =========================
    def _fuzz_field_in_layer(self, layers: List[Any], field_desc, fname: str, merged_field_mapping: Optional[List[dict]] = None, force_fuzz: bool = False) -> List[int]:
        """
        Fuzz a specific field across multiple layers (batch processing) with dictionary and mutation support.
        
        Args:
            layers: List of packet layers containing the field to fuzz
            field_desc: Scapy field descriptor object
            fname: Name of the field to fuzz
            merged_field_mapping: Advanced field mapping configuration
            force_fuzz: If True, skip probabilistic weight checking and force fuzzing
            
        Returns:
            List of indexes (0-based) of layers that were NOT fuzzed (due to skipping or failure)
        """
        # Use the first layer as template for FuzzField extraction and configuration
        if not layers:
            return []
        
        template_layer = layers[0]
        
        # Selection is now handled at the batch level, so proceed with fuzzing
        logger.debug(f"Fuzzing field {template_layer.__class__.__name__}.{fname} across {len(layers)} layers")
        
        # Extract campaign defaults from merged_field_mapping for this field
        campaign_defaults = None
        if merged_field_mapping:
            for field_mapping in merged_field_mapping:
                if field_mapping.get('field_name') == fname:
                    campaign_defaults = field_mapping
                    break
        
        # Extract FuzzField configuration with campaign-level defaults
        raw_field_value = getattr(template_layer, fname, None)
        fuzzfield_config = self._extract_fuzzfield_config(raw_field_value, campaign_defaults)
        
        # Type-aware mutation using FieldInfo + mutate_field API
        field_info = self._build_field_info(template_layer, field_desc, fname)

        # Extract all FuzzField-dependent data BEFORE removing wrappers
        # 1) Honor explicit values if present, merged with campaign/default-derived values
        explicit_values = list(fuzzfield_config.get('values') or [])
        try:
            merged_values = self.dictionary_manager.get_field_values(
                template_layer, 
                fname
            ) or []
            # Preserve order while removing duplicates: explicit first, then merged
            explicit_values = list(dict.fromkeys(explicit_values + merged_values))
        except Exception:
            pass
        
        # Get dictionary entries while FuzzField is still intact
        dictionaries = self._get_field_dictionary_entries(fuzzfield_config, fname, field_desc, template_layer)
        current_value = None if (FuzzField is not None and isinstance(raw_field_value, FuzzField)) else raw_field_value
        
        # NOW remove FuzzField wrapper from all layers to avoid leaking into Scapy
        # This happens AFTER all FuzzField-dependent operations (extraction, weight check, etc.)
        for layer in layers:
            current_field_value = getattr(layer, fname, None)
            if (fuzzfield_config['is_fuzzfield'] or 
                (FuzzField is not None and isinstance(current_field_value, FuzzField))):
                try:
                    # Store the current value first in case we need to debug
                    current_val = getattr(layer, fname, None)
                    delattr(layer, fname)
                    # Verify removal worked
                    after_val = getattr(layer, fname, "FIELD_REMOVED")
                    if fname in self.CRITICAL_FIELDS:
                        logger.debug(f"FuzzField removal: {layer.__class__.__name__}.{fname} was {type(current_val)}, now {type(after_val) if after_val != 'FIELD_REMOVED' else 'REMOVED'}")
                except Exception as e:
                    if fname in self.CRITICAL_FIELDS:
                        logger.debug(f"Failed to unset {layer.__class__.__name__}.{fname} via delattr (FuzzField removal): {e}")
        
        # Track which layer indexes were successfully fuzzed
        unfuzzed_indexes = []
        successfully_fuzzed_count = 0
        
        # Reset tracking for this field - this should track only current field mutations
        self.current_fuzzed_fields = []
        
        if explicit_values:
            # Apply explicit values to all layers
            pick_rng = self.config.rng or random
            for layer_idx, layer in enumerate(layers):
                # Store original value to compare against changes
                original_value = getattr(layer, fname, None)
                
                try:
                    pick = pick_rng.choice(explicit_values)
                except Exception:
                    pick = explicit_values[0]
                
                    if self._validate_and_assign(field_info, pick, layer, fname):
                        if fname in self.CRITICAL_FIELDS:
                            logger.debug(f"Assigned {layer.__class__.__name__}.{fname} to {pick} (explicit value)")
                        # Track that this field was fuzzed only if the value actually changed
                        new_value = getattr(layer, fname, None)
                        if self._field_value_changed(original_value, new_value):
                            successfully_fuzzed_count += 1
                        else:
                            unfuzzed_indexes.append(layer_idx)
                    else:
                        unfuzzed_indexes.append(layer_idx)            # If we successfully fuzzed some layers with explicit values, return unfuzzed indexes
            if successfully_fuzzed_count > 0:
                # Track that this field type had successful mutations
                self.current_fuzzed_fields = [f"{template_layer.__class__.__name__}.{fname}"] if successfully_fuzzed_count > 0 else []
                return unfuzzed_indexes
            # If explicit values failed for all layers, fall back to mutation path

        # 2) Mutator-based generation with retries for all layers
        # Use pre-extracted dictionaries and current_value
        
        # Call the updated _mutate_with_retries with the full layer list
        unfuzzed_indexes = self._mutate_with_retries(field_info, layers, field_desc, fname, current_value, dictionaries, fuzzfield_config, force_fuzz)
        
        # Check if any layers were successfully fuzzed by mutation
        mutation_success_count = len(layers) - len(unfuzzed_indexes)
        if mutation_success_count > 0:
            # Track that this field type had successful mutations
            self.current_fuzzed_fields = [f"{template_layer.__class__.__name__}.{fname}"]
        
        return unfuzzed_indexes

    # --- Helper: FieldInfo ---
    def _build_field_info(self, layer: Packet, field_desc: Field, fname: str) -> FieldInfo:
        kind = 'unknown'
        min_v = None
        max_v = None
        enum_map = None
        signed = False
        max_len = None

        # Determine kind and constraints based on scapy field types
        if isinstance(field_desc, (ByteField, ShortField, IntField, BitField)):
            kind = 'numeric'
            # Approximate ranges
            try:
                # BitField has size; others we infer by class
                if isinstance(field_desc, BitField):
                    bits = getattr(field_desc, 'size', 8)
                    min_v, max_v = 0, (1 << bits) - 1
                elif isinstance(field_desc, ByteField):
                    min_v, max_v = 0, 0xFF
                elif isinstance(field_desc, ShortField):
                    min_v, max_v = 0, 0xFFFF
                elif isinstance(field_desc, IntField):
                    min_v, max_v = 0, 0xFFFFFFFF
            except Exception:
                min_v, max_v = 0, 0xFFFFFFFF
        if isinstance(field_desc, FlagsField):
            kind = 'flags'
            min_v, max_v = 0, 0xFFFFFFFF
        if isinstance(field_desc, (EnumField, IntEnumField)):
            kind = 'enum'
            try:
                enum_map = getattr(field_desc, 'enum', None)
            except Exception:
                enum_map = None
            min_v, max_v = 0, 0xFFFFFFFF
        if isinstance(field_desc, StrField):
            kind = 'string'
            # StrField may accept any length; set soft cap
            max_len = 2048
            # Debug logging for field type detection
            logger.debug(f"_build_field_info: field {fname} is StrField, setting kind='string', field_type={type(field_desc)}")
        # Options/list detection by name heuristic
        if fname == 'options':
            kind = 'options'

        layer_name = getattr(layer, 'name', layer.__class__.__name__)
        return FieldInfo(fname, layer_name, kind, min_v, max_v, enum_map, signed, max_len)

    def _select_mutator_for_field(self, fuzzfield_config: Dict[str, Any]):
        # Prefer explicit field-level mutator list
        mutator_candidates = []
        prefs = fuzzfield_config.get('mutators') or self.config.mutator_preference
        for m in prefs:
            mval = getattr(m, 'value', m)
            if mval == 'dictionary_only' and self.dictionary_only_mutator:
                mutator_candidates.append(self.dictionary_only_mutator)
            elif mval == 'libfuzzer' and self.libfuzzer_mutator:
                mutator_candidates.append(self.libfuzzer_mutator)
            elif mval == 'scapy' and self.scapy_mutator:
                mutator_candidates.append(self.scapy_mutator)
        if mutator_candidates:
            chosen = random.choice(mutator_candidates)
            # Record chosen mutator usage for reporting
            mutator_name = self._record_mutator_usage(chosen)
            return chosen
        # Fallback: any available
        chosen = self.scapy_mutator or self.dictionary_only_mutator or self.libfuzzer_mutator
        mutator_name = self._record_mutator_usage(chosen)
        return chosen

    def _mutate_with_retries(self, field_info: FieldInfo, layers: List[Packet], field_desc, fname: str,
                              current_value: Any, dictionaries: List[bytes], fuzzfield_config: Dict[str, Any], force_fuzz: bool = False) -> List[int]:
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
        # Select mutator first (before retry loop to allow corpus initialization)
        mutator = None
        if field_info.kind in ('options', 'list') and self.scapy_mutator:
            mutator = self.scapy_mutator
        else:
            mutator = self._select_mutator_for_field(fuzzfield_config)

        # Initialize corpus if mutator supports it
        if mutator and hasattr(mutator, 'initialize'):
            try:               
                # Initialize corpus and get candidate values
                mutator.initialize(field_info, dictionaries, self.config.rng)
            except (AttributeError, NotImplementedError, Exception) as e:
                logger.debug(f"Corpus initialization failed for {fname}: {e}")

        # Track which layer indexes were not successfully fuzzed
        unfuzzed_indexes = []
        
        # Iterate through all layers and attempt mutation
        effective_weight = self.get_final_field_weight(layers[0], field_desc, fname)
        for layer_idx, layer in enumerate(layers):
            # Store original value to compare against changes
            original_value = getattr(layer, fname, None)
            success = False
            
            # Apply weight check for this specific layer (unless force_fuzz is True)
            # This ensures layer weight scaling applies correctly per layer depth
            
            if not force_fuzz and not self.should_fuzz(effective_weight, self.config.rng):
                # If skipping fuzz, do NOT delete the field - this preserves the original value
                if fname in self.CRITICAL_FIELDS:
                    logger.debug(f"Skipping {layer.__class__.__name__}.{fname} (weight-based skip, effective_weight={effective_weight:.6f})")
                unfuzzed_indexes.append(layer_idx)
                continue
            
            # Try a few time to mutate a field
            attempts = 0
            max_attempts = 3
            last_err = None

            while attempts < max_attempts and not success:
                attempts += 1

                #Mutate the field
                try:
                    mutated_value = None
                    if field_info.kind in ('options', 'list') and self.scapy_mutator:
                        mutator_to_use = self.scapy_mutator
                    else:
                        mutator_to_use = mutator  # Use the pre-selected mutator

                    if mutator_to_use and hasattr(mutator_to_use, 'mutate_field'):
                        mutated_value = mutator_to_use.mutate_field(field_info, current_value, dictionaries, self.config.rng, layer)  # type: ignore
                    else:
                        mutated_value = current_value

                    if self._validate_and_assign(field_info, mutated_value, layer, fname):
                        success = True
                        # Track that this field was fuzzed only if the value actually changed
                        new_value = getattr(layer, fname, None)
                        if not self._field_value_changed(original_value, new_value):
                            # Value didn't actually change, consider this unfuzzed
                            unfuzzed_indexes.append(layer_idx)
                            success = False
                except Exception as e:
                    last_err = e
                    continue

            # If all attempts failed for this layer
            if not success:
                layer_name = getattr(layer, 'name', layer.__class__.__name__)
                logger.warning(f"Field mutation failed after {attempts} attempts: {layer_name}.{fname}: {last_err}")
                key = (layer_name, fname)
                self.field_mutation_failures[key] = self.field_mutation_failures.get(key, 0) + 1
                unfuzzed_indexes.append(layer_idx)
                
                # Revert to original when available; else drop attr to let Scapy resolve defaults
                try:
                    if current_value is not None:
                        setattr(layer, fname, current_value)
                        if fname in self.CRITICAL_FIELDS:
                            logger.debug(f"Set {layer.__class__.__name__}.{fname} to {current_value} via setattr (mutation fallback)")
                    else:
                        try:
                            delattr(layer, fname)
                            if fname in self.CRITICAL_FIELDS:
                                logger.debug(f"Unset {layer.__class__.__name__}.{fname} via delattr (mutation fallback)")
                        except Exception:
                            if fname in self.CRITICAL_FIELDS:
                                logger.debug(f"Failed to unset {layer.__class__.__name__}.{fname} via delattr (mutation fallback)")
                except Exception:
                    pass
            else:
                if fname in self.CRITICAL_FIELDS:
                    logger.debug(f"Mutate with retries result for {layer.__class__.__name__}.{fname}: {getattr(layer, fname, None)}")

        return unfuzzed_indexes

    def _validate_and_assign(self, field_info: FieldInfo, value: Any, layer: Packet, fname: str) -> bool:
        """Validate, normalize, and assign a field value with basic constraints and a quick serialize smoke-check.

        Goals (low-risk):
        - Normalize list/options fields.
        - For numeric/flags: coerce to int and clamp within [min_value, max_value] when provided.
        - For enums: require the coerced int to be in enum_map keys (no implicit remap here).
        - Attempt a quick serialization to catch deferred Scapy packing errors; revert and return False on failure.
        """
        # Debug logging for validation attempts
        logger.debug(f"_validate_and_assign: field={fname}, kind={field_info.kind}, value={repr(value)}, layer={layer.__class__.__name__}")

        def _coerce_int(v: Any) -> Optional[int]:
            # Accept ints/bools directly
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, int):
                return v
            # Accept bytes/str with optional 0x prefix
            s: Optional[str] = None
            if isinstance(v, (bytes, bytearray)):
                try:
                    s = v.decode('utf-8', errors='ignore').strip()
                except Exception:
                    return None
            elif isinstance(v, str):
                s = v.strip()
            if s is None or s == "":
                return None
            try:
                if s.lower().startswith(("0x", "+0x", "-0x")):
                    return int(s, 16)
                return int(s, 10)
            except Exception:
                return None

        def _clamp(v: int, mn: Optional[int], mx: Optional[int]) -> int:
            if mn is not None and v < mn:
                v = mn
            if mx is not None and v > mx:
                v = mx
            return v

        try:
            normalized = value

            # Normalize container-like fields
            if field_info.kind in ('options', 'list'):
                if value is None:
                    normalized = []
                # We'll validate on a cloned layer before touching the real one
            else:
                # Numeric / flags / enum handling
                if field_info.kind in ('numeric', 'flags', 'enum'):
                    ival = _coerce_int(value)
                    if ival is None:
                        # Reject if cannot be coerced to int for these kinds
                        logger.debug(f"_validate_and_assign: Failed to coerce {repr(value)} to int for {fname}")
                        return False
                    if field_info.kind in ('numeric', 'flags'):
                        ival = _clamp(ival, field_info.min_value, field_info.max_value)
                        normalized = ival
                    elif field_info.kind == 'enum':
                        # Enforce membership if enum_map is present
                        enum_map = field_info.enum_map if isinstance(field_info.enum_map, dict) else None
                        if enum_map and ival not in enum_map.keys():
                            logger.debug(f"_validate_and_assign: Value {ival} not in enum_map for {fname}")
                            return False
                        normalized = ival
                        
            # String kind should pass through as-is
            if field_info.kind == 'string':
                logger.debug(f"_validate_and_assign: String field {fname}, normalized={repr(normalized)}")
                        
            # Quick serialize smoke-check on a cloned layer to avoid side effects
            try:
                layer_clone = copy.deepcopy(layer)
                logger.debug(f"_validate_and_assign: Testing assignment of {repr(normalized)} to {fname}")
                setattr(layer_clone, fname, normalized)
                logger.debug(f"_validate_and_assign: Assignment successful, testing serialization")
                _ = bytes(layer_clone)
                logger.debug(f"_validate_and_assign: Serialization successful")
            except Exception as e:
                logger.debug(f"_validate_and_assign: Serialize test failed for {fname}: {e}")
                return False

            # Apply to the real layer now that validation passed
            try:
                setattr(layer, fname, normalized)
                logger.debug(f"_validate_and_assign: Final assignment successful for {fname}")
            except Exception as e:
                logger.debug(f"_validate_and_assign: Final assignment failed for {fname}: {e}")
                return False
            return True
        except Exception as e:
            logger.debug(f"_validate_and_assign: Exception during validation of {fname}: {e}")
            return False


    def _fuzz_packet_level(self, packet, iterations):
        """
        Fuzz the packet at the byte level.

        This method treats the entire packet as a raw byte sequence and applies
        mutation using the configured mutator and relevant dictionaries. The mutation
        is protocol-agnostic and can alter any part of the packet, including headers,
        payloads, and structure. This approach is useful for aggressive fuzzing and
        discovering vulnerabilities that may not be exposed by field-level mutations.
        The resulting packets may be malformed or non-compliant with protocol standards.
        """
        results = []
        
        # Select mutator: if a list is provided, randomly choose among available ones; otherwise use a simple fallback
        mutator = None
        prefs = self.config.mutator_preference or []
        candidates = []
        for m in prefs:
            mv = getattr(m, 'value', m)
            if mv == 'libfuzzer' and self.libfuzzer_mutator:
                candidates.append(self.libfuzzer_mutator)
            elif mv == 'dictionary_only' and self.dictionary_only_mutator:
                candidates.append(self.dictionary_only_mutator)
            elif mv == 'scapy' and self.scapy_mutator:
                candidates.append(self.scapy_mutator)
        if candidates:
            mutator = random.choice(candidates)
        else:
            # Simple fallback order
            mutator = self.libfuzzer_mutator or self.dictionary_only_mutator or self.scapy_mutator
        # Record usage of selected mutator
        try:
            mutator_name = self._record_mutator_usage(mutator)
        except Exception:
            mutator_name = "unknown"
        
        for _ in range(iterations):
            # Convert packet to bytes
            packet_bytes = bytes(packet)
            
            # Get relevant dictionaries for this packet type
            dictionary_paths = self.dictionary_manager.get_packet_dictionaries(packet)
            try:
                dictionaries = self.dictionary_manager.get_dictionary_entries(dictionary_paths)
            except FileNotFoundError:
                return []
            except Exception:
                return []
            
            # Mutate the packet bytes using the selected mutator
            fuzzed_bytes = mutator.mutate_bytes(packet_bytes, dictionaries) if mutator else packet_bytes
            
            # Try to reconstruct the packet
            try:
                # Use the same packet class to parse the fuzzed bytes
                fuzzed_packet = packet.__class__(fuzzed_bytes)
                results.append(fuzzed_packet)
            except Exception:
                # If reconstruction fails, create a raw packet  
                from scapy.packet import Raw
                fuzzed_packet = Raw(fuzzed_bytes)
                results.append(fuzzed_packet)
        return results
    
    def _find_layer_with_field(self, packet, field_name):
        """Find the layer that contains the specified field using Scapy's native methods"""
        # Use Scapy's layers() to get all layer classes, then check each one
        for layer_class in packet.layers():
            layer = packet.getlayer(layer_class)
            if layer and hasattr(layer, field_name):
                return layer
        return None
    
    # =========================
    # FuzzField & Dictionary Utilities
    # =========================
    def _extract_fuzzfield_config(self, field_value: Any, campaign_defaults: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Extract fuzzing configuration from a FuzzField object, merging with campaign-level defaults.
        
        Configuration hierarchy (highest to lowest priority):
        1. FuzzField-level settings (if field_value is a FuzzField)
        2. Campaign-level settings (from merged_field_mapping)
        3. Default fallback values
        """
        # Start with default configuration
        config = {
            'values': [],
            'dictionaries': [],
            'fuzz_weight': 1.0,
            'mutators': [],
            'scapy_fuzz_weight': 0.0,
            'dictionary_only_weight': 0.0,
            'simple_field_fuzz_weight': 0.0,
            'is_fuzzfield': False
        }
        
        # Apply campaign-level defaults if provided
        if campaign_defaults:
            if 'values' in campaign_defaults:
                config['values'] = list(campaign_defaults['values'])
            if 'dictionaries' in campaign_defaults:
                config['dictionaries'] = list(campaign_defaults['dictionaries'])
            if 'fuzz_weight' in campaign_defaults:
                config['fuzz_weight'] = campaign_defaults['fuzz_weight']
            if 'mutators' in campaign_defaults:
                config['mutators'] = list(campaign_defaults['mutators'])
        
        # Override with FuzzField-level settings if present
        if FuzzField and isinstance(field_value, FuzzField):
            config.update({
                'values': field_value.values or config['values'],
                'dictionaries': field_value.dictionaries or config['dictionaries'],
                'fuzz_weight': field_value.fuzz_weight if field_value.fuzz_weight is not None else config['fuzz_weight'],
                'mutators': field_value.mutators or config['mutators'],
                'scapy_fuzz_weight': field_value.scapy_fuzz_weight,
                'dictionary_only_weight': field_value.dictionary_only_weight,
                'is_fuzzfield': True
            })
        
        return config
    
    def _get_field_dictionary_entries(self, fuzzfield_config, field_name, field_desc, layer_or_packet=None):
        """
        Get dictionary entries for a field from FuzzField configuration.
        - If FuzzField specifies dictionaries, load and merge all entries from those files (ignore load errors).
        - Otherwise, fall back to the default dictionary lookup logic using DictionaryManager.
        - All error handling and logging for dictionary file loads is handled in DictionaryManager.
        Returns a list of dictionary entries (bytes), or an empty list if none found or on error.
        """
        logger.debug(f"_get_field_dictionary_entries: field_name={field_name}, fuzzfield_dictionaries={fuzzfield_config['dictionaries']}")
        if fuzzfield_config['dictionaries']:
            all_entries = []
            for dict_path in fuzzfield_config['dictionaries']:
                try:
                    # Load entries from each specified dictionary file (errors ignored, handled in DictionaryManager)
                    entries = self.dictionary_manager._load_dictionary_file(dict_path)
                    all_entries.extend(entries)
                except Exception:
                    continue  # Ignore failed dictionary loads
            logger.debug(f"_get_field_dictionary_entries: field_name={field_name}, loaded {len(all_entries)} entries from FuzzField dictionaries")
            return all_entries
        else:
            # Use the actual layer or packet if available, else fall back to dummy Raw
            packet_for_lookup = layer_or_packet
            if packet_for_lookup is None:
                from scapy.packet import Raw
                packet_for_lookup = Raw()
            dictionary_paths = self.dictionary_manager.get_field_dictionaries(
                packet_for_lookup, 
                field_name
            )
            logger.debug(f"_get_field_dictionary_entries: field_name={field_name}, dictionary_paths={dictionary_paths}")
            try:
                # All error handling/logging is in DictionaryManager
                entries = self.dictionary_manager.get_dictionary_entries(dictionary_paths)
                logger.debug(f"_get_field_dictionary_entries: field_name={field_name}, loaded {len(entries)} entries from default dictionaries")
                return entries
            except FileNotFoundError:
                logger.debug(f"_get_field_dictionary_entries: field_name={field_name}, FileNotFoundError - returning empty list")
                return []

    def _materialize_fuzzfields_on_clone(self, packet_clone: Packet) -> None:
        """
        Remove or replace FuzzField attributes on the cloned packet's layers using Scapy's native methods.
        If a FuzzField is found, set the field to its chosen value, or delete the attribute if None.
        """
        try:
            from fuzzing_framework import FuzzField as _FuzzField
        except Exception:
            return
        
        # Use Scapy's layers() method to iterate through all layers
        for layer_class in packet_clone.layers():
            cursor = packet_clone.getlayer(layer_class)
            if cursor is None:
                continue
                
            for desc in getattr(cursor, 'fields_desc', []):
                fname = getattr(desc, 'name', None)
                if not fname:
                    continue
                val = getattr(cursor, fname, None)
                if isinstance(val, _FuzzField):
                    chosen = val.choose_value()
                    if chosen is None:
                        # Remove attribute so Scapy resolves default
                        if hasattr(cursor, fname):
                            delattr(cursor, fname)
                            if fname == 'ihl':
                                logger.debug(f"[DEBUG] Unset IP.ihl via delattr (materialize) on layer {getattr(cursor, 'name', type(cursor).__name__)}")
                    else:
                        setattr(cursor, fname, chosen)
                        if fname == 'ihl':
                            logger.debug(f"[DEBUG] Set IP.ihl to {chosen} via setattr (materialize) on layer {getattr(cursor, 'name', type(cursor).__name__)}")

    # =========================
    # Mutation Logic
    # =========================
        # Removed old _mutate_field_value logic in favor of type-aware mutate_field API
        # TODO: Evaluate moving this function into DictionaryManager to centralize dictionary resolution.


    def get_final_field_weight(self, layer, field_desc, field_name: Optional[str] = None) -> float:
        """Calculate the final effective weight for a field, applying layer weight scaling if enabled."""
        # All fields use advanced mapping/override logic for weight
        base_weight = self.dictionary_manager.get_field_weight(
            layer, 
            field_name or getattr(field_desc, 'name', '')
        )

        # Optional: apply layer-based scaling so outer layers are fuzzed less when scaling factor is lower
        effective_weight = base_weight
        try:
            if getattr(self.config, 'enable_layer_weight_scaling', True):
                # Determine depth: number of layers from current to innermost
                # Innermost layer should not be scaled at all (depth 0)
                # Outer layers get scaled down based on their distance from innermost
                from scapy.packet import NoPayload
                # Walk to count remaining payload chain from current layer
                depth_below = 0
                cursor = layer
                while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
                    depth_below += 1
                    cursor = cursor.payload
                # Load scaling factor: campaign override via config or default mapping constant
                scale = self.config.layer_weight_scaling if (self.config.layer_weight_scaling is not None) else DEFAULT_LAYER_SCALING
                
                # Apply scaling: base * (scale ** depth_below). 
                # Lower scale means outer layers (higher depth_below) get reduced more
                # If depth_below==0 (innermost), multiplier=1.0 (no scaling)
                # If depth_below==1, multiplier=scale
                # If depth_below==2, multiplier=scale^2, etc.
                if isinstance(scale, (int, float)) and scale > 0:
                    effective_weight = base_weight * (float(scale) ** int(max(depth_below, 0)))
                
                # Only log weight calculations once per unique field to reduce log spam
                if not hasattr(self, '_logged_weights'):
                    self._logged_weights = set()
                
                layer_name = getattr(layer, 'name', type(layer).__name__)
                weight_id = f"{layer_name}:{field_name}:{base_weight}:{depth_below}"
                if weight_id not in self._logged_weights:
                    logger.debug(f"layer={layer_name}, field={field_name}, base_weight={base_weight}, depth_below={depth_below}, scale={scale}, effective_weight={effective_weight}")
                    self._logged_weights.add(weight_id)
        except Exception as e:
            logger.debug(f"Exception for layer={getattr(layer, 'name', type(layer).__name__)}, field={field_name}: {e}")
            effective_weight = base_weight

        return effective_weight

    @staticmethod
    def should_fuzz(resolved_weight: float, rng: Optional[random.Random] = None) -> bool:
        """Return True if fuzzing should occur, given the resolved probability and optional random generator."""
        effective_weight = min(max(resolved_weight, 0.0), 1.0)
        rand = (rng or random).random()
        return rand < effective_weight
