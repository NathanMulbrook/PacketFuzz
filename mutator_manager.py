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
from dictionary_manager import DictionaryManager
from packet_extensions import install_packet_extensions

# Import default directories
try:
    from fuzzing_framework import DEFAULT_LOG_DIR
except ImportError:
    # Fallback if circular import - define locally
    DEFAULT_LOG_DIR = "logs"
from utils.packet_report import write_packet_report

logger = logging.getLogger(__name__)

# Import FuzzField for direct handling
try:
    from fuzzing_framework import FuzzField
except ImportError:
    FuzzField = None

# Import mutators for type checking
try:
    from mutators.dictionary_only_mutator import DictionaryOnlyMutator
except Exception:
    DictionaryOnlyMutator = None  # type: ignore
try:
    from mutators.libfuzzer_mutator import LibFuzzerMutator
except Exception:
    LibFuzzerMutator = None  # type: ignore
try:
    from mutators.scapy_mutator import ScapyMutator
except Exception:
    ScapyMutator = None  # type: ignore

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
    Mutator Manager for PacketFuzzing campaigns
    
    Manages mutator selection and orchestrates fuzzing operations.
    Delegates all mutation logic to specialized mutators.
    """
    
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
            from mutators.libfuzzer_mutator import LibFuzzerMutator
            self.libfuzzer_mutator = LibFuzzerMutator()
        except Exception as e:
            logger.error(f"Failed to initialize LibFuzzerMutator: {e}")
            self.libfuzzer_mutator = None
        try:
            from mutators.dictionary_only_mutator import DictionaryOnlyMutator
            self.dictionary_only_mutator = DictionaryOnlyMutator()
        except Exception as e:
            logger.error(f"Failed to initialize DictionaryOnlyMutator: {e}")
            self.dictionary_only_mutator = None
        try:
            from mutators.scapy_mutator import ScapyMutator
            self.scapy_mutator = ScapyMutator()
        except Exception as e:
            logger.error(f"Failed to initialize ScapyMutator: {e}")
            self.scapy_mutator = None
        # Track per-field mutation failures for reporting/analysis
        self.field_mutation_failures: Dict[Tuple[str, str], int] = {}

    
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
        write_packet_report([packet], file_path=get_log_file_path("fuzz_fields_input_report.txt"))
        results: List[Packet] = []
        for _ in range(iterations):
            fuzzed_packet = copy.deepcopy(packet)
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
            # attempt to ensure that at least one field is fuzze, but if all layers have weights set to 0 we dont want to fuzz
            # Rather than checking all the weights to see if if they are 0, we just try a few times if nothing is fuzzed
            # The assumption is that if any field is allowed to be fuzzed then at least one will be after a few attempts
            # 4 attempts was chosen as a good default, this may need adjusted later
            # with the way this is now handled we can probably remove the FORCE_FUZZ constant, but for now its fine to leave
            while not fuzzed_any and attempt_no < 4:
                for idx, (layer, field_desc, fname) in enumerate(candidate_fields):
                    # Only force fuzz the first field if none have been fuzzed yet
                    if not fuzzed_any or idx == 0:
                        fuzzed = self._fuzz_field_in_layer(layer, field_desc, fname, merged_field_mapping)
                        fuzzed_any = True if fuzzed else fuzzed_any
                    else:
                        fuzzed = self._fuzz_field_in_layer(layer, field_desc, fname, merged_field_mapping)
                        fuzzed_any = True if fuzzed else fuzzed_any
                if not FORCE_FUZZ:
                    # Only attempt to fuzz the packet once if force fuzz is not set
                    break
                attempt_no += 1
            results.append(fuzzed_packet)
        # Write report of all fuzzed packets
        try:
            write_packet_report(results, file_path=get_log_file_path("fuzz_fields_output_report.txt"))
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
            except Exception:
                setattr(layer, fname, None)

        # Apply field weighting and exclusion logic
        # Priority order: 1) Campaign/dictionary values 2) FuzzField values 3) Let Scapy resolve
        if self._should_skip_field(layer, field_desc, fname):
            # If skipping fuzz, prefer letting Scapy resolve by deleting the attr
            try:
                delattr(layer, fname)
            except Exception:
                setattr(layer, fname, None)
            return False

        # Type-aware mutation using FieldInfo + mutate_field API
        field_info = self._build_field_info(layer, field_desc, fname)

        # 1) Honor explicit values if present, merged with campaign/default-derived values
        #TODO evaluate if this flow is actually correct, values should be used as fallback if fuzzing is not done base on the weights
        explicit_values = list(fuzzfield_config.get('values') or [])
        try:
            merged_values = self.dictionary_manager.get_field_values(layer, fname) or []
            # Preserve order while removing duplicates: explicit first, then merged
            combined = list(dict.fromkeys(explicit_values + merged_values))
            explicit_values = combined
        except Exception:
            pass
        if explicit_values:
            pick_rng = self.config.rng or random
            try:
                pick = pick_rng.choice(explicit_values)
            except Exception:
                pick = explicit_values[0]
            if self._validate_and_assign(field_info, pick, layer, fname):
                return True
            # If the explicit pick fails validation/assignment, fall back to mutation path

        # 2) Mutator-based generation with retries
        dictionaries = self._get_field_dictionary_entries(fuzzfield_config, fname, field_desc, layer)
        current_value = None if (FuzzField is not None and isinstance(raw_field_value, FuzzField)) else raw_field_value
        return self._mutate_with_retries(field_info, layer, fname, current_value, dictionaries, fuzzfield_config)

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
            return random.choice(mutator_candidates)
        # Fallback: any available
        return self.scapy_mutator or self.dictionary_only_mutator or self.libfuzzer_mutator

    def _mutate_with_retries(self, field_info: FieldInfo, layer: Packet, fname: str,
                              current_value: Any, dictionaries: List[bytes], fuzzfield_config: Dict[str, Any]) -> bool:
        attempts = 0
        max_attempts = 3
        last_err: Any = None

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
                    mutated_value = mutator.mutate_field(field_info, current_value, dictionaries, self.config.rng, layer)
                else:
                    mutated_value = current_value

                if self._validate_and_assign(field_info, mutated_value, layer, fname):
                    return True
            except Exception as e:
                last_err = e
                continue

        layer_name = getattr(layer, 'name', layer.__class__.__name__)
        logger.warning(f"[FUZZ] Field mutation failed after {attempts} attempts: {layer_name}.{fname}: {last_err}")
        key: Tuple[str, str] = (layer_name, fname)
        self.field_mutation_failures[key] = self.field_mutation_failures.get(key, 0) + 1
        # Revert to original when available; else drop attr to let Scapy resolve defaults
        try:
            if current_value is not None:
                setattr(layer, fname, current_value)
            else:
                try:
                    delattr(layer, fname)
                except Exception:
                    setattr(layer, fname, None)
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
            import copy as _cpy
            try:
                layer_clone = _cpy.deepcopy(layer)
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
            dictionary_paths = self.dictionary_manager.get_field_dictionaries(packet_for_lookup, field_name)
            try:
                # All error handling/logging is in DictionaryManager
                return self.dictionary_manager.get_dictionary_entries(dictionary_paths)
            except FileNotFoundError:
                return []
            except Exception:
                return []

    # =========================
    # Mutation Logic
    # =========================
        # Removed old _mutate_field_value logic in favor of type-aware mutate_field API
        # TODO: Evaluate moving this function into DictionaryManager to centralize dictionary resolution.


    def _should_skip_field(self, layer, field_desc, field_name: Optional[str] = None) -> bool:
        """Determine if a field should be skipped during fuzzing, using resolved weight logic for all fields (simple and complex)."""
        # All fields use advanced mapping/override logic for weight
        weight = self.dictionary_manager.get_field_weight(layer, field_name or getattr(field_desc, 'name', ''))
        return not MutatorManager.should_fuzz(weight, self.config.rng)

    @staticmethod
    def should_fuzz(resolved_weight: float, rng: Optional[random.Random] = None) -> bool:
        """Return True if fuzzing should occur, given the resolved probability and optional random generator."""
        effective_weight = min(max(resolved_weight, 0.0), 1.0)
        rand = (rng or random).random()
        return rand < effective_weight
