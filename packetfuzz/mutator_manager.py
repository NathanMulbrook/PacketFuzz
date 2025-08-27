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
FORCE_FUZZ = True  # Force fuzzing at least one field if none are fuzzed
# TODO: Review FORCE_FUZZ behavior to ensure it still adds value alongside the retry loop in fuzz_fields.
# TODO: Review FORCE_FUZZ behavior vs retry loop to ensure semantics are clear and necessary.


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
        # Track mutator usage counts for reporting
        self.mutator_usage_counts: Dict[str, int] = {}

    def _record_mutator_usage(self, mutator_obj: Any) -> None:
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
            self.mutator_usage_counts[name] = self.mutator_usage_counts.get(name, 0) + 1
        except Exception:
            pass

    
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
            field_variants = self.fuzz_fields(packet, iterations // 2)
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
        # Debug logging only in verbose mode
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            write_debug_packet_log([packet], file_path=get_log_file_path("fuzz_fields_input_report.txt"), title="Fuzz Fields Input")
        results: List[Packet] = []
        for _ in range(iterations):
            fuzzed_packet = copy.deepcopy(packet)
            # Ensure the deep-copied packet does not contain FuzzField wrappers
            # Replace any FuzzField instances on the cloned packet with a concrete
            # value chosen by the FuzzField (or remove the attribute to let
            # Scapy resolve defaults). This keeps the original packet's
            # FuzzField metadata intact while ensuring the clone serializes.
            try:
                self._materialize_fuzzfields_on_clone(fuzzed_packet)
            except Exception:
                # Best-effort: do not fail fuzzing if materialization has issues
                logger.debug("Failed to materialize FuzzField instances on packet clone")
            # Build candidate field list: either a single named field or all fields in all layers
            if field_name:
                candidate_fields = [(layer, layer.get_field(field_name), field_name)]
            else:
                candidate_fields = []
                layer = fuzzed_packet
                # Traverse all layers and collect all fields
                while not isinstance(layer, NoPayload):
                    for field_desc in layer.fields_desc:
                        candidate_fields.append((layer, field_desc, field_desc.name))
                    layer = layer.payload
            # Fuzz all candidate fields, but always ensure at least one is fuzzed
            fuzzed_any = False
            attempt_no = 0
            
            # Check if layer weight scaling is enabled and aggressive (< 0.5)
            # If so, respect the user's intent for less fuzzing and disable retries entirely
            layer_scaling_enabled = getattr(self.config, 'enable_layer_weight_scaling', True)
            scaling_factor = self.config.layer_weight_scaling if (self.config.layer_weight_scaling is not None) else None
            if scaling_factor is None:
                scaling_factor = DEFAULT_LAYER_SCALING
            
            # If layer scaling is aggressive (< 0.5), disable retries entirely to respect scaling intent
            use_retries = not (layer_scaling_enabled and scaling_factor < 0.5)
            max_attempts = 4 if use_retries else 1
            
            # attempt to ensure that at least one field is fuzzed, but if all layers have weights set to 0 we dont want to fuzz
            # Rather than checking all the weights to see if if they are 0, we just try a few times if nothing is fuzzed
            # The assumption is that if any field is allowed to be fuzzed then at least one will be after a few attempts
            # When layer weight scaling is aggressive (< 0.5), we disable retries entirely to respect the user's intent
            while not fuzzed_any and attempt_no < max_attempts:
                for idx, (layer, field_desc, fname) in enumerate(candidate_fields):
                    fuzzed = self._fuzz_field_in_layer(layer, field_desc, fname, merged_field_mapping)
                    fuzzed_any = True if fuzzed else fuzzed_any
                if not FORCE_FUZZ or not use_retries:
                    # Only attempt to fuzz the packet once if force fuzz is not set or retries are disabled
                    break
                attempt_no += 1
            results.append(fuzzed_packet)
        # Write debug report of all fuzzed packets (only in debug mode)
        if VERBOSITY_LEVEL >= 3:  # Only in debug mode
            try:
                write_debug_packet_log(results, file_path=get_log_file_path("fuzz_fields_output_report.txt"), title="Fuzz Fields Output")
            except Exception as e:
                logger.debug(f"Failed to write packet report: {e}")
                # Continue execution even if report writing fails
        return results

    # =========================
    # Field/Packet Fuzzing Internals
    # =========================
    def _fuzz_field_in_layer(self, layer, field_desc, fname: str, merged_field_mapping: Optional[List[dict]] = None) -> bool:
        """
        Fuzz a specific field in a layer with dictionary and mutation support.
        
        Args:
            layer: The packet layer containing the field
            field_desc: Scapy field descriptor object
            fname: Name of the field to fuzz
            merged_field_mapping: Advanced field mapping configuration
            
        Returns:
            True if field was fuzzed, False if skipped
        """
        # Extract FuzzField configuration if present in the field value (for dictionaries only)
        raw_field_value = getattr(layer, fname, None)
        fuzzfield_config = self._extract_fuzzfield_config(raw_field_value)
        if fuzzfield_config['is_fuzzfield']:
            # Remove the FuzzField wrapper to avoid leaking into Scapy
            try:
                delattr(layer, fname)
                if fname in self.CRITICAL_FIELDS:
                    logger.debug(f"Unset {layer.__class__.__name__}.{fname} via delattr (FuzzField removal)")
            except Exception:
                if fname in self.CRITICAL_FIELDS:
                    logger.debug(f"Failed to unset {layer.__class__.__name__}.{fname} via delattr (FuzzField removal)")
        # Apply field weighting and exclusion logic
        # Priority order: 1) Campaign/dictionary values 2) FuzzField values 3) Let Scapy resolve
        # NOTE: Weight check moved below dictionary value retrieval to apply scaling to all fields
        
        # Type-aware mutation using FieldInfo + mutate_field API
        field_info = self._build_field_info(layer, field_desc, fname)

        # 1) Honor explicit values if present, merged with campaign/default-derived values
        #TODO evaluate if this flow is actually correct, values should be used as fallback if fuzzing is not done base on the weights
        explicit_values = list(fuzzfield_config.get('values') or [])
        try:
            merged_values = self.dictionary_manager.get_field_values(
                layer, 
                fname
            ) or []
            # Preserve order while removing duplicates: explicit first, then merged
            combined = list(dict.fromkeys(explicit_values + merged_values))
            explicit_values = combined
        except Exception:
            pass
        
        # Apply weight check AFTER dictionary values are retrieved but BEFORE using them
        # This ensures layer weight scaling applies to all fields, including dictionary-based ones
        if self._should_skip_field(layer, field_desc, fname):
            # If skipping fuzz, do NOT delete the field - this preserves the original value
            # The previous logic of deleting the field caused Scapy to auto-generate random values
            if fname in self.CRITICAL_FIELDS:
                logger.debug(f"Skipping {layer.__class__.__name__}.{fname} (weight-based skip)")
            return False
            
        if explicit_values:
            pick_rng = self.config.rng or random
            try:
                pick = pick_rng.choice(explicit_values)
            except Exception:
                pick = explicit_values[0]
            if self._validate_and_assign(field_info, pick, layer, fname):
                if fname in self.CRITICAL_FIELDS:
                    logger.debug(f"Assigned {layer.__class__.__name__}.{fname} to {pick} (explicit value)")
                return True
            # If the explicit pick fails validation/assignment, fall back to mutation path

        # 2) Mutator-based generation with retries
        dictionaries = self._get_field_dictionary_entries(fuzzfield_config, fname, field_desc, layer)
        current_value = None if (FuzzField is not None and isinstance(raw_field_value, FuzzField)) else raw_field_value
        result = self._mutate_with_retries(field_info, layer, fname, current_value, dictionaries, fuzzfield_config)
        if fname in self.CRITICAL_FIELDS:
            logger.debug(f"Mutate with retries result for {layer.__class__.__name__}.{fname}: {getattr(layer, fname, None)}")
        return result

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
            self._record_mutator_usage(chosen)
            return chosen
        # Fallback: any available
        chosen = self.scapy_mutator or self.dictionary_only_mutator or self.libfuzzer_mutator
        self._record_mutator_usage(chosen)
        return chosen

    def _mutate_with_retries(self, field_info, layer, fname,
                              current_value, dictionaries, fuzzfield_config):
        attempts = 0
        max_attempts = 3
        last_err = None

        while attempts < max_attempts:
            attempts += 1
            try:
                # Centralize options/list special-case here: use scapy mutator when possible
                mutator = None
                if field_info.kind in ('options', 'list') and self.scapy_mutator:
                    mutator = self.scapy_mutator
                else:
                    mutator = self._select_mutator_for_field(fuzzfield_config)

                mutated_value = None
                if mutator and hasattr(mutator, 'mutate_field'):
                    mutated_value = mutator.mutate_field(field_info, current_value, dictionaries, self.config.rng, layer)  # type: ignore
                else:
                    mutated_value = current_value

                if self._validate_and_assign(field_info, mutated_value, layer, fname):
                    return True
            except Exception as e:
                last_err = e
                continue

        layer_name = getattr(layer, 'name', layer.__class__.__name__)
        logger.warning(f"Field mutation failed after {attempts} attempts: {layer_name}.{fname}: {last_err}")
        key = (layer_name, fname)
        self.field_mutation_failures[key] = self.field_mutation_failures.get(key, 0) + 1
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
        return False

    def _validate_and_assign(self, field_info: FieldInfo, value: Any, layer: Packet, fname: str) -> bool:
        """Validate, normalize, and assign a field value with basic constraints and a quick serialize smoke-check.

        Goals (low-risk):
        - Normalize list/options fields.
        - For numeric/flags: coerce to int and clamp within [min_value, max_value] when provided.
        - For enums: require the coerced int to be in enum_map keys (no implicit remap here).
        - Attempt a quick serialization to catch deferred Scapy packing errors; revert and return False on failure.
        """

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
                        return False
                    if field_info.kind in ('numeric', 'flags'):
                        ival = _clamp(ival, field_info.min_value, field_info.max_value)
                        normalized = ival
                    elif field_info.kind == 'enum':
                        # Enforce membership if enum_map is present
                        enum_map = field_info.enum_map if isinstance(field_info.enum_map, dict) else None
                        if enum_map and ival not in enum_map.keys():
                            return False
                        normalized = ival
            # Quick serialize smoke-check on a cloned layer to avoid side effects
            try:
                layer_clone = copy.deepcopy(layer)
                setattr(layer_clone, fname, normalized)
                _ = bytes(layer_clone)
            except Exception:
                return False

            # Apply to the real layer now that validation passed
            try:
                setattr(layer, fname, normalized)
            except Exception:
                return False
            return True
        except Exception:
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
            self._record_mutator_usage(mutator)
        except Exception:
            pass
        
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
        """Find the layer that contains the specified field"""
        layer = packet
        while not isinstance(layer, NoPayload):
            if hasattr(layer, field_name):
                return layer
            layer = layer.payload
        return None
    
    # =========================
    # FuzzField & Dictionary Utilities
    # =========================
    def _extract_fuzzfield_config(self, field_value: Any, campaign_defaults: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Extract fuzzing configuration from a FuzzField object.
        """
        if FuzzField and isinstance(field_value, FuzzField):
            # Use FuzzField attributes directly, no default_value
            return {
                'values': field_value.values,
                'dictionaries': field_value.dictionaries,
                'fuzz_weight': field_value.fuzz_weight,
                'mutators': field_value.mutators,
                'scapy_fuzz_weight': field_value.scapy_fuzz_weight,
                'dictionary_only_weight': field_value.dictionary_only_weight,
                'is_fuzzfield': True
            }
        else:
            return {
                'values': [],
                'dictionaries': [],
                'fuzz_weight': 1.0,
                'mutators': [],
                'scapy_fuzz_weight': 0.0,
                'dictionary_only_weight': 0.0,
                'simple_field_fuzz_weight': 0.0,
                'is_fuzzfield': False
            }
    
    def _get_field_dictionary_entries(self, fuzzfield_config, field_name, field_desc, layer_or_packet=None):
        """
        Get dictionary entries for a field from FuzzField configuration.
        - If FuzzField specifies dictionaries, load and merge all entries from those files (ignore load errors).
        - Otherwise, fall back to the default dictionary lookup logic using DictionaryManager.
        - All error handling and logging for dictionary file loads is handled in DictionaryManager.
        Returns a list of dictionary entries (bytes), or an empty list if none found or on error.
        """
        if fuzzfield_config['dictionaries']:
            all_entries = []
            for dict_path in fuzzfield_config['dictionaries']:
                try:
                    # Load entries from each specified dictionary file (errors ignored, handled in DictionaryManager)
                    entries = self.dictionary_manager._load_dictionary_file(dict_path)
                    all_entries.extend(entries)
                except Exception:
                    continue  # Ignore failed dictionary loads
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
            try:
                # All error handling/logging is in DictionaryManager
                return self.dictionary_manager.get_dictionary_entries(dictionary_paths)
            except FileNotFoundError:
                return []

    def _materialize_fuzzfields_on_clone(self, packet_clone: Packet) -> None:
        """
        Remove or replace FuzzField attributes on the cloned packet's layers.
        If a FuzzField is found, set the field to its chosen value, or delete the attribute if None.
        """
        try:
            from fuzzing_framework import FuzzField as _FuzzField
        except Exception:
            return
        cursor = packet_clone
        from scapy.packet import NoPayload
        while cursor is not None and not isinstance(cursor, NoPayload):
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
            cursor = getattr(cursor, 'payload', None)

    # =========================
    # Mutation Logic
    # =========================
        # Removed old _mutate_field_value logic in favor of type-aware mutate_field API
        # TODO: Evaluate moving this function into DictionaryManager to centralize dictionary resolution.


    def _should_skip_field(self, layer, field_desc, field_name: Optional[str] = None) -> bool:
        """Determine if a field should be skipped during fuzzing, using resolved weight logic for all fields (simple and complex)."""
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
                
                logger.debug(f"layer={getattr(layer, 'name', type(layer).__name__)}, field={field_name}, base_weight={base_weight}, depth_below={depth_below}, scale={scale}, effective_weight={effective_weight}")
        except Exception as e:
            logger.debug(f"Exception for layer={getattr(layer, 'name', type(layer).__name__)}, field={field_name}: {e}")
            effective_weight = base_weight

        return not MutatorManager.should_fuzz(effective_weight, self.config.rng)

    @staticmethod
    def should_fuzz(resolved_weight: float, rng: Optional[random.Random] = None) -> bool:
        """Return True if fuzzing should occur, given the resolved probability and optional random generator."""
        effective_weight = min(max(resolved_weight, 0.0), 1.0)
        rand = (rng or random).random()
        return rand < effective_weight
