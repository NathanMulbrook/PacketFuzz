"""
libFuzzer integration module

This module provides the interface to the libFuzzer C extension
for high-performance mutation operations.
"""

# Standard library imports
import ctypes
import logging
import random
import re
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

# Third-party imports
from scapy.fields import Field

# Local imports
from .base import BaseMutator, MutatorRegistry

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MAX_OUTPUT_SIZE = 1024
DEFAULT_OUTPUT_BUFFER_MULTIPLIER = 2


class LibFuzzerMutator(BaseMutator):
    """
    libFuzzer-based mutator using the C extension with multi-round iterative mutations.
    
    Provides high-performance mutations using libFuzzer's proven algorithms.
    Implements multi-round mutation strategy where each round uses the output
    from the previous round as input, similar to how libFuzzer builds upon
    previous corpus entries to discover deeper bugs.
    
    Requires the C extension to be compiled and available.
    """
    
    @classmethod
    def get_name(cls) -> str:
        """Override to maintain backward compatibility with 'libfuzzer' name"""
        return "libfuzzer"
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize LibFuzzer mutator.
        
        Args:
            seed: Random seed for reproducible mutations
        """
        super().__init__(seed)
        self._seed = seed
        self._lib = None
        self._dictionaries_loaded = False  # Track if dictionaries are already loaded
        self._rng = random.Random(seed) if seed is not None else random.Random()
        
        self._load_library()
    
    def _load_library(self) -> None:
        """Load the libFuzzer C extension library"""
        try:
            # Look for the compiled library
            lib_path = self._find_library_path()
            if lib_path and Path(lib_path).exists():
                self._lib = ctypes.CDLL(lib_path)
                self._setup_function_signatures()
            else:
                raise RuntimeError("LibFuzzer extension library not found. Compile the extension first.")
        except Exception as e:
            if "LibFuzzer extension library not found" in str(e):
                raise
            logger.error(f"Could not load libFuzzer extension: {e}")
            raise RuntimeError("LibFuzzer extension failed to load. Check compilation.")
    
    def _find_library_path(self) -> Optional[str]:
        """Find the compiled libFuzzer extension library (Linux only)."""
        current_dir = Path(__file__).resolve().parent
        # Only Linux is currently supported
        linux_lib = 'libscapy_libfuzzer.so'
        path = current_dir / linux_lib
        if path.exists():
            return str(path)
        return None
    
    def _setup_function_signatures(self) -> None:
        """Setup ctypes function signatures for the C library."""
        if not self._lib:
            return
        # Dictionary loading for LibFuzzer support
        self._lib.load_dictionaries_native.argtypes = [
            ctypes.POINTER(ctypes.c_char_p), # dictionary entries
            ctypes.c_size_t                  # dict_count
        ]
        self._lib.load_dictionaries_native.restype = ctypes.c_int
        # Initialize libFuzzer
        self._lib.init_libfuzzer.argtypes = [ctypes.c_uint32]
        self._lib.init_libfuzzer.restype = ctypes.c_int
        # Initialize with seed if provided
        if self._seed is not None:
            self._lib.init_libfuzzer(self._seed)
        # Setup mutate_with_dict_enhanced signature
        self._lib.mutate_with_dict_enhanced.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # input_data
            ctypes.c_size_t,                 # input_size
            ctypes.POINTER(ctypes.c_uint8),  # output_data
            ctypes.c_size_t,                 # max_output_size
            ctypes.POINTER(ctypes.c_char_p), # dict_entries
            ctypes.c_size_t,                 # dict_count
            ctypes.c_uint32                  # seed
        ]
        self._lib.mutate_with_dict_enhanced.restype = ctypes.c_size_t

    def load_dictionaries_for_native_support(self, dictionaries: List[str]) -> bool:
        """
        Load dictionaries into LibFuzzer's native dictionary system.
        Args:
            dictionaries: List of dictionary strings to load
        Returns:
            True if loaded or no dictionaries to load, False if error
        """
        # Ensure the LibFuzzer C extension library is loaded before proceeding
        if not self._lib:
            return False
        if not dictionaries:
            logger.debug("No dictionaries provided to load; skipping dictionary loading.")
            return True
        try:
            # Convert to C format
            dict_entries = (ctypes.c_char_p * len(dictionaries))()
            for i, entry in enumerate(dictionaries):
                dict_entries[i] = ctypes.c_char_p(entry.encode('utf-8', errors='ignore'))
            # Load into LibFuzzer memory only
            result = self._lib.load_dictionaries_native(dict_entries, len(dictionaries))
            logger.debug(f"LibFuzzer dictionary loading result: {result} (entries: {len(dictionaries)})")
            if result == -1:
                logger.error("Error loading dictionaries: allocation or internal error.")
                return False
            else:
                # Verify actual loaded count to determine success
                try:
                    loaded_count = self._lib.get_loaded_dict_count()
                    if loaded_count > 0:
                        logger.debug(f"Successfully loaded {loaded_count} dictionary entries into LibFuzzer")
                        return True
                    else:
                        if dictionaries:
                            logger.error(f"No dictionaries loaded, but non-empty dictionary list was provided! (entries: {len(dictionaries)})")
                        else:
                            logger.debug("No dictionaries loaded (empty list or None provided).")
                        return True  # Still return True to not block fuzzing
                except Exception as e:
                    logger.warning(f"Failed to verify dictionary loading: {e}")
                    # Assume success if we can't verify
                    return True
        except Exception as e:
            logger.error(f"Exception loading dictionaries: {e}")
            return False
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data using libFuzzer with multi-round iterative mutations"""
        if not self.is_libfuzzer_available():
            raise RuntimeError("LibFuzzer C extension is not available. Please compile and install the extension.")
        return self._mutate_with_libfuzzer_multiround(data, dictionaries)
    
    def _mutate_with_libfuzzer_multiround(self, data: bytes, dictionaries: Optional[List[bytes]] = None,
                                        max_length: Optional[int] = None) -> bytes:
        """
        Multi-round LibFuzzer mutation using random rounds (0-30).
        
        IMPORTANT: NO HARDCODED SEEDS OR CORPUS MANAGEMENT!
        - LibFuzzer handles corpus and crossover internally
        - We only provide the input and let LibFuzzer do its magic
        - Multiple rounds allow LibFuzzer to build upon previous mutations
        - Round count is random (0-30) for variety
        """
        # Random round count between 0 and 3 (reduced for performance)
        round_count = self._rng.randint(0, 3)
        
        max_length = max_length or DEFAULT_MAX_OUTPUT_SIZE
        
        if round_count == 0:
            # No multi-round: single mutation with provided seed
            return self._mutate_with_libfuzzer(data, dictionaries, max_length)
        
        # Multi-round mutation - let LibFuzzer handle the complexity
        current_data = data
        for round_num in range(round_count):
            if round_num == 0:
                # First round: no seed, let LibFuzzer start fresh
                current_data = self._mutate_with_libfuzzer(b"", dictionaries, max_length)
            else:
                # Subsequent rounds: use previous output as input (evolutionary)
                current_data = self._mutate_with_libfuzzer(current_data, dictionaries, max_length)
            
            # Basic length check to prevent runaway growth
            if len(current_data) > max_length * 2:
                current_data = current_data[:max_length]
        
        return current_data

    def _mutate_with_libfuzzer(self, data: bytes, dictionaries: Optional[List[bytes]] = None, max_length: Optional[int] = None) -> bytes:
        """Perform mutation using the libFuzzer C extension with enhanced parameters for longer output"""
        # Allow empty data for LibFuzzer to generate from scratch
        
        # Prepare input data (handle empty case)
        input_size = len(data) if data else 1  # LibFuzzer needs at least 1 byte input buffer
        if data:
            input_data = (ctypes.c_uint8 * input_size)(*data)
        else:
            input_data = (ctypes.c_uint8 * 1)(0)  # Single null byte for empty input
        
        # Prepare output buffer with enhanced size based on max_length constraint
        base_multiplier = DEFAULT_OUTPUT_BUFFER_MULTIPLIER
        original_data_size = len(data) if data else 1  # Use original data size for calculations
        if max_length and max_length > original_data_size:
            # Allow buffer to grow significantly for fields with large max_length
            base_multiplier = max(base_multiplier, max_length // max(original_data_size, 1))
        
        max_output_size = max(
            original_data_size * base_multiplier, 
            DEFAULT_MAX_OUTPUT_SIZE,
            max_length * 2 if max_length else 0  # Give LibFuzzer room to expand beyond max_length (we'll clamp later)
        )
        output_data = (ctypes.c_uint8 * max_output_size)()
        
        # Check if the enhanced mutation function is available
        if self._lib is None or not hasattr(self._lib, 'mutate_with_dict_enhanced'):
            raise RuntimeError('mutate_with_dict_enhanced not available in C extension')
        
        lib = self._lib  # type: ignore
        
        if dictionaries:
            # Convert dictionaries to string format
            dict_strings = [d.decode('utf-8', errors='ignore') for d in dictionaries]
            dict_entries = (ctypes.c_char_p * len(dict_strings))()
            for i, entry in enumerate(dict_strings):
                dict_entries[i] = ctypes.c_char_p(entry.encode('utf-8', errors='ignore'))
            
            result_size = lib.mutate_with_dict_enhanced(
                input_data, input_size,
                output_data, max_output_size,
                dict_entries, len(dict_strings),
                0  # seed (0 means use internal random)
            )
        else:
            empty_dict = (ctypes.c_char_p * 0)()
            result_size = lib.mutate_with_dict_enhanced(
                input_data, input_size,
                output_data, max_output_size,
                empty_dict, 0,  # no dictionaries
                0  # seed
            )
        
        if result_size > 0:
            return bytes(output_data[:result_size])
        else:
            return data

    def is_libfuzzer_available(self) -> bool:
        """Check if the LibFuzzer C extension is available and loaded."""
        return self._lib is not None

    def _ensure_dictionaries_loaded(self, dictionaries: List[bytes]) -> bool:
        """
        Ensure dictionaries are loaded into LibFuzzer's native dictionary system.
        
        Converts byte dictionaries to string format and loads them into the C extension
        for enhanced mutation capabilities.
        
        Args:
            dictionaries: List of dictionary entries as bytes
            
        Returns:
            True if dictionaries were loaded successfully or no loading needed,
            False if LibFuzzer is not available or loading failed
        """
        if not self.is_libfuzzer_available():
            return False
            
        try:
            # Convert bytes dictionaries to string format for C extension
            dict_strings = []
            for d in dictionaries:
                if isinstance(d, bytes):
                    dict_strings.append(d.decode('utf-8', errors='ignore'))
                else:
                    dict_strings.append(str(d))
            
            # Load dictionaries into memory only (no corpus)
            return self.load_dictionaries_for_native_support(dict_strings)
        except Exception as e:
            logger.warning(f"Failed to load dictionaries into LibFuzzer: {e}")
            return False

    # --- New API: type-aware field mutation ---
    def mutate_field(self,
                     field_info: Any,
                     dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None,
                     layer: Optional[Any] = None) -> Any:
        """
        Mutate a field value using LibFuzzer's advanced mutation algorithms.
        
        Provides type-aware mutation based on field kind (string, numeric, enum, etc.)
        with multi-round iterative mutations for deep fuzzing capabilities.
        
        Args:
            field_info: Field metadata containing type, constraints, and current value
            dictionaries: Optional dictionary entries for enhanced mutations
            rng: Random number generator (compatibility parameter, not used)
            layer: Packet layer context (compatibility parameter, not used)
            
        Returns:
            Mutated field value appropriate for the field type, or current value
            if LibFuzzer is not available
        """
        # If libfuzzer is not available, return current value to allow manager to try other mutators
        current_value = getattr(field_info, 'current_value', None)
        # Try both 'kind' and 'field_kind' for compatibility
        kind = getattr(field_info, 'kind', None) or getattr(field_info, 'field_kind', 'unknown')

        if not self.is_libfuzzer_available():
            return current_value

        # Helper: mutate some bytes, return bytes
        def mutate_bytes_seed(b: bytes) -> bytes:
            """Helper function to mutate bytes with error handling."""
            return self._mutate_with_libfuzzer_multiround(b, dictionaries)

        # Helper: parse int from bytes/str
        def parse_int(data: bytes | str) -> Optional[int]:
            """Extract integer value from bytes or string data."""
            s = data.decode('utf-8', errors='ignore') if isinstance(data, (bytes, bytearray)) else str(data)
            m = re.search(r"([+-]?0x[0-9a-fA-F]+|[+-]?\d+)", s)
            if not m:
                return None
            token = m.group(1)
            base = 16 if token.lower().startswith('0x') else 10
            return int(token, base)

        # Helper: clamp
        def clamp(v: int, mn: Optional[int], mx: Optional[int]) -> int:
            """Clamp integer value to specified min/max bounds."""
            if mn is not None and v < mn:
                v = mn
            if mx is not None and v > mx:
                v = mx
            return v

        if kind in ('numeric', 'flags', 'enum'):
            seed = ("" if current_value is None else str(current_value)).encode('utf-8', errors='ignore')
            mutated = self._mutate_with_libfuzzer_multiround(seed, dictionaries)
            val = parse_int(mutated)
            if val is None:
                # Fallback to seed parsed
                val = parse_int(seed)
            if val is None:
                val = 0
            val = clamp(val, getattr(field_info, 'min_value', None), getattr(field_info, 'max_value', None))
            # Enum mapping to allowed values if provided
            enum_map = getattr(field_info, 'enum_map', None)
            if enum_map and isinstance(enum_map, dict):
                # Enum map uses integer keys
                allowed_ints = list(enum_map.keys())
                if allowed_ints:
                    if val not in allowed_ints:
                        val = allowed_ints[val % len(allowed_ints)]
            return val

        if kind == 'string':
            # CRITICAL: ONLY LIBFUZZER OUTPUT CAN BE USED AS SEEDS!
            # NO current_value, NO dictionary entries, NO hardcoded seeds
            # The ONLY seed values passed to LibFuzzer should be:
            # 1. Empty bytes (for first round to start fresh)
            # 2. Output from previous LibFuzzer rounds (for evolution)
            # Dictionaries influence LibFuzzer INTERNALLY, not as seed input!
            
            field_name = getattr(field_info, 'field_name', 'Unknown')
            
            # Always start with empty seed - let LibFuzzer generate everything
            seed = b""
            
            if hasattr(field_info, 'field_name') and field_info.field_name in ['Method', 'Path', 'Host', 'User_Agent']:
                logger.info(f"LibFuzzer: Mutating {field_info.field_name} with empty seed")
            
            # Use multi-round mutation - LibFuzzer handles dictionaries internally
            max_len = getattr(field_info, 'max_length', None)
            mutated = self._mutate_with_libfuzzer_multiround(seed, dictionaries, max_len)
            
            if hasattr(field_info, 'field_name') and field_info.field_name in ['Method', 'Path', 'Host', 'User_Agent']:
                logger.info(f"LibFuzzer: Got mutated bytes: {mutated} (length: {len(mutated)})")
            
            s = mutated.decode('utf-8', errors='ignore')
                
            # Apply field-specific length constraints for realistic fuzzing
            max_len = getattr(field_info, 'max_length', None)
            
            if isinstance(max_len, int) and max_len > 0:
                if hasattr(field_info, 'field_name') and field_info.field_name in ['Method', 'Path', 'Host', 'User_Agent']:
                    logger.debug(f"LibFuzzer: Clamping {field_info.field_name} from length {len(s)} to max_length {max_len}")
                s = s[:max_len]
                
            return s

        if kind in ('options', 'list'):
            # Let the manager/scapy mutator handle options
            return None

        if kind == 'raw':
            seed = b"" if current_value is None else (current_value if isinstance(current_value, (bytes, bytearray)) else str(current_value).encode('utf-8', errors='ignore'))
            return self._mutate_with_libfuzzer_multiround(seed, dictionaries)

        # Unknown kinds: no change
        return current_value

    def initialize(self, field_info: Any, dictionaries: List[Any], rng: Optional[random.Random] = None) -> bool:
        """
        Initialize LibFuzzer with dictionaries for this field type.
        
        Args:
            field_info: Dataclass-like object describing field type, name, constraints
            dictionaries: List of dictionary entries for this field type  
            rng: Optional RNG for randomization
            
        Returns:
            True if initialization successful, False otherwise
        """
        if not self.is_libfuzzer_available():
            return False
            
        # Only load dictionaries once to avoid memory corruption in C extension
        if dictionaries and len(dictionaries) > 0 and not self._dictionaries_loaded:
            # Load dictionaries into LibFuzzer's memory
            try:
                # Convert dictionaries to string format and load
                dict_strings = []
                for d in dictionaries:
                    if isinstance(d, bytes):
                        dict_strings.append(d.decode('utf-8', errors='ignore'))
                    else:
                        dict_strings.append(str(d))
                
                success = self.load_dictionaries_for_native_support(dict_strings)
                if success:
                    self._dictionaries_loaded = True
                    self.initialized = True
                    logger.debug(f"Initialized LibFuzzer with {len(dictionaries)} dictionary entries")
                return success
            except Exception as e:
                logger.warning(f"Failed to initialize LibFuzzer with dictionaries: {e}")
                return False
        
        # Even without dictionaries, consider the mutator initialized
        self.initialized = True
        return True
            

    
    def _bytes_to_field_value(self, data: bytes, field_info: Any) -> Any:
        """Convert mutated bytes back to appropriate field value based on field type."""
        kind = getattr(field_info, 'kind', None) or getattr(field_info, 'field_kind', 'unknown')
        
        if kind in ('numeric', 'flags', 'enum'):
            # Try to parse as integer
            s = data.decode('utf-8', errors='ignore')
            m = re.search(r"([+-]?0x[0-9a-fA-F]+|[+-]?\d+)", s)
            if m:
                token = m.group(1)
                base = 16 if token.lower().startswith('0x') else 10
                val = int(token, base)
                
                # Apply constraints
                min_val = getattr(field_info, 'min_value', None)
                max_val = getattr(field_info, 'max_value', None)
                if min_val is not None and val < min_val:
                    val = min_val
                if max_val is not None and val > max_val:
                    val = max_val
                
                # Handle enum mapping
                enum_map = getattr(field_info, 'enum_map', None)
                if enum_map and isinstance(enum_map, dict):
                    allowed_ints = list(enum_map.keys())
                    if allowed_ints and val not in allowed_ints:
                        val = allowed_ints[val % len(allowed_ints)]
                
                return val
            return 0
            
        elif kind == 'string':
            s = data.decode('utf-8', errors='ignore')
            max_len = getattr(field_info, 'max_length', None)
            if isinstance(max_len, int) and max_len > 0:
                s = s[:max_len]
            return s
                
        elif kind == 'raw':
            return data
            
        else:
            # For unknown kinds, return as string
            return data.decode('utf-8', errors='ignore')
    
    def teardown(self) -> bool:
        """Clean up LibFuzzer resources."""
        self._dictionaries_loaded = False
        return True


# Removed manual registration - now uses auto-discovery
