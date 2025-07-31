"""
Mutator Manager for Scapy Fuzzer

Manages mutator selection and orchestrates fuzzing campaigns.
Delegates all actual mutation logic to specialized mutators in the mutators/ directory.
"""

# Standard library imports
import copy
import logging
import os
import random
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Type
from pathlib import Path

# Third-party imports
from scapy.fields import Field, AnyField, BitField, FlagsField, EnumField, StrField, IntField
from scapy.packet import Packet, NoPayload, fuzz
from scapy.volatile import VolatileValue

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
    mutator_preference: list[str] = field(default_factory=lambda: ["libfuzzer"])
    global_dict_config_path: Optional[str] = None  # Path to global dictionary configuration
    rng: Optional[random.Random] = None  # Optional random generator for reproducibility

    def __str__(self) -> str:
        return f"FuzzConfig(mode={self.mode.value}, max_mutations={self.max_mutations})"

    def __repr__(self) -> str:
        return (f"FuzzConfig(mode={self.mode}, max_mutations={self.max_mutations}, "
                f"use_dictionaries={self.use_dictionaries}, mutator_preference={self.mutator_preference})")


class MutatorManager:
    """
    Mutator Manager for Scapy fuzzing campaigns
    
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
    
    def fuzz_fields(self, packet: Packet, iterations: int = 1, field_name: Optional[str] = None, merged_field_mapping: Optional[list] = None) -> List[Packet]:
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
        results: list[Packet] = []
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
        # Extract FuzzField configuration if present in the field value
        raw_field_value = getattr(layer, fname, None)
        fuzzfield_config = self._extract_fuzzfield_config(raw_field_value)

        # Clear FuzzField from layer so Scapy can resolve it properly if not set by fuzzing
        if fuzzfield_config['is_fuzzfield']:
            try:
                delattr(layer, fname)
            except Exception:
                setattr(layer, fname, None)

        # Apply field weighting and exclusion logic
        # Priority order: 1) Campaign/dictionary values 2) FuzzField values 3) Let Scapy resolve
        if self._should_skip_field(layer, field_desc, fname):
            # Get dictionary values first (highest priority)
            merged_values = self.dictionary_manager.get_field_values(layer, fname)
            if merged_values:
                skip_value = random.choice(merged_values)
                setattr(layer, fname, skip_value)
            elif fuzzfield_config['values']:
                # Fallback to FuzzField values if no dictionary entries
                skip_value = random.choice(fuzzfield_config['values'])
                setattr(layer, fname, skip_value)
            else:
                # No values available - remove field to let Scapy auto-resolve
                try:
                    delattr(layer, fname)
                except Exception:
                    setattr(layer, fname, None)
            return False

        # Perform actual field mutation using selected mutator
        else:
            mutated_value = self._mutate_field_value(
                None,  # No default_value
                field_desc,
                self._get_field_dictionary_entries(fuzzfield_config, fname, field_desc, layer),
                fuzzfield_config,
                fname,
                layer  # Pass the layer for value lookup
            )
            try:
                setattr(layer, fname, mutated_value)
                return True
            except Exception as setattr_error:
                # Handle various field assignment errors gracefully
                error_msg = str(setattr_error)
                if any(error_phrase in error_msg for error_phrase in [
                    "Name or service not known", 
                    "nodename nor servname provided",
                    "unsupported operand type",
                    "invalid literal for int()",
                    "ValueError",
                    "TypeError"
                ]):
                    logger.debug(f"Field assignment error for field {fname} with value '{mutated_value}': {error_msg}")
                    return False
                else:
                    logger.debug(f"Unexpected error setting field {fname} to value '{mutated_value}': {setattr_error}")
                    return False

    def _fuzz_packet_level(self, packet: Packet, iterations: int) -> List[Packet]:
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
        
        # Select mutator based on configuration preference
        mutator = None
        if self.config.mutator_preference == "dictionary_only" and self.dictionary_only_mutator:
            mutator = self.dictionary_only_mutator
        elif self.config.mutator_preference == "libfuzzer" and self.libfuzzer_mutator:
            mutator = self.libfuzzer_mutator
        elif self.config.mutator_preference == "scapy" and self.scapy_mutator:
            mutator = self.scapy_mutator
        
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
    
    def _find_layer_with_field(self, packet: Packet, field_name: str) -> Optional[Packet]:
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
    
    def _get_field_dictionary_entries(self, fuzzfield_config: Dict[str, Any], field_name: str, field_desc: Union[Field, AnyField], layer_or_packet: Optional[Packet] = None) -> List[bytes]:
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
    def _mutate_field_value(self, current_value: Any, field_desc: Union[Field, AnyField], 
                                         dictionary_entries: List[bytes], fuzzfield_config: Dict[str, Any], 
                                         field_name: str, layer: Optional[Packet] = None) -> Any:
        """
        This function handles selection of mutator and actually calling the mutator
        Mutate a field value using FuzzField configuration and campaign defaults.
        Mutation strategy is selected based on weights and mutator preferences:
        - With probability dictionary_only_weight, use a random dictionary value.
        - With probability scapy_fuzz_weight, use Scapy's built-in fuzz().
        - If preferred mutator is 'dictionary_only', use the dictionary mutator if available.
        - If using LibFuzzerMutator and a dictionary is present, use per-field corpus logic and mutate with LibFuzzer.
        - If none of the above, use a random value from the values list if available, else return the original value.
        """
        import tempfile
        import shutil
        # Select mutator using hierarchical preference system:
        # 1. Field-level preference (from FuzzField.mutators) - highest priority
        # 2. Global config preference (from FuzzConfig.mutator_preference) - fallback
        # 3. System default fallback (libfuzzer → dictionary_only) - last resort
        mutator = None
        mutator_preference = fuzzfield_config['mutators']
        mutator_candidates = []
        if mutator_preference:
            for m in mutator_preference:
                mval = getattr(m, 'value', m)
                if mval == "dictionary_only" and self.dictionary_only_mutator:
                    mutator_candidates.append(self.dictionary_only_mutator)
                elif mval == "libfuzzer" and self.libfuzzer_mutator:
                    mutator_candidates.append(self.libfuzzer_mutator)
                elif mval == "scapy" and self.scapy_mutator:
                    mutator_candidates.append(self.scapy_mutator)
        if mutator_candidates:
            mutator = random.choice(mutator_candidates)

        # LEVEL 2: If no field-specific preference was found, use global config preference
        if not mutator:
            mutator_preference = self.config.mutator_preference
            mutator_candidates = []
            for m in mutator_preference:
                mval = getattr(m, 'value', m)
                if mval == "dictionary_only" and self.dictionary_only_mutator:
                    mutator_candidates.append(self.dictionary_only_mutator)
                elif mval == "libfuzzer" and self.libfuzzer_mutator:
                    mutator_candidates.append(self.libfuzzer_mutator)
                elif mval == "scapy" and self.scapy_mutator:
                    mutator_candidates.append(self.scapy_mutator)
            if mutator_candidates:
                mutator = random.choice(mutator_candidates)

        # LEVEL 3: probability-based mutator selection that overrides the above
        # With probability dictionary_only_weight, set mutator to dictionary_only_mutator
        if fuzzfield_config['dictionary_only_weight'] > 0.0 and dictionary_entries:
            if random.random() < fuzzfield_config['dictionary_only_weight']:
                mutator = self.dictionary_only_mutator
        # With probability scapy_fuzz_weight, use Scapy's built-in fuzz()
        if fuzzfield_config['scapy_fuzz_weight'] > 0.0:
            if random.random() < fuzzfield_config['scapy_fuzz_weight']:
                mutator = self.scapy_mutator

        # Convert dictionary entries from bytes to strings for mutators that require string input (e.g., DictionaryOnlyMutator)
        dict_strings = [d.decode('utf-8', errors='ignore') for d in dictionary_entries] if dictionary_entries else []
        if mutator_preference and any((getattr(m, 'value', m) == "dictionary_only") for m in (fuzzfield_config['mutators'] or [])):
            if dictionary_entries and DictionaryOnlyMutator and isinstance(mutator, DictionaryOnlyMutator) and hasattr(mutator, 'mutate_dictionary_only'):
                return mutator.mutate_dictionary_only(  # type: ignore[attr-defined]
                    str(current_value).encode('utf-8', errors='ignore'),
                    dict_strings
                ).decode('utf-8', errors='ignore')
            elif dictionary_entries and mutator is not None and hasattr(mutator, 'mutate_bytes'):
                input_data = str(current_value).encode('utf-8', errors='ignore')
                return mutator.mutate_bytes(
                    input_data,
                    dictionary_entries
                )
        # If using LibFuzzerMutator and a dictionary is present, use per-field corpus logic
        if dictionary_entries and LibFuzzerMutator and isinstance(mutator, LibFuzzerMutator):
            temp_dir = tempfile.mkdtemp(prefix=f"scapyfuzz_corpus_{field_name}_")
            try:
                if hasattr(mutator, 'generate_dictionary_seed'):
                    mutator.generate_dictionary_seed(dict_strings, temp_dir)  # type: ignore[attr-defined]
                os.environ["SCAPY_LIBFUZZER_CORPUS"] = temp_dir
                mutated = mutator.mutate_bytes(
                    str(current_value).encode('utf-8', errors='ignore'),
                    dictionary_entries
                )
                return mutated.decode('utf-8', errors='ignore')
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
                if os.environ.get("SCAPY_LIBFUZZER_CORPUS") == temp_dir:
                    del os.environ["SCAPY_LIBFUZZER_CORPUS"]
        # Final fallback when no other mutation applies:
        # 1. FuzzField values (if no mutator was selected) - highest priority
        # 2. Campaign/dictionary values (from field mappings) - medium priority
        # 3. Leave empty so Scapy resolves it - lowest priority
        if mutator is None:
            if fuzzfield_config['values']:
                return random.choice(fuzzfield_config['values'])
            merged_values = self.dictionary_manager.get_field_values(layer, field_name) if layer is not None else []
            if merged_values:
                return random.choice(merged_values)
            # No value: leave empty so Scapy resolves it
            return None
        # If no mutation applies and no fallback values, return None so Scapy resolves it
        return current_value


    def _should_skip_field(self, layer: Packet, field_desc: Union[Field, AnyField], field_name: Optional[str] = None) -> bool:
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
