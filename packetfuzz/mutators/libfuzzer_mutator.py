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

# Third-party imports
from scapy.fields import Field

# Local imports
from .base import BaseMutator

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MAX_OUTPUT_SIZE = 1024
DEFAULT_OUTPUT_BUFFER_MULTIPLIER = 2


class LibFuzzerMutator(BaseMutator):
    """
    libFuzzer-based mutator using the C extension.
    
    Provides high-performance mutations using libFuzzer's proven algorithms.
    Requires the C extension to be compiled and available.
    """
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._seed = seed
        self._lib = None
        self._dictionaries_loaded = False  # Track if dictionaries are already loaded
        self._load_library()
    
    def _load_library(self):
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
    
    def _setup_function_signatures(self):
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
            if result == -1:
                logger.error("Error loading dictionaries: allocation or internal error.")
                return False
            elif result == 0:
                if dictionaries:
                    logger.error(f"No dictionaries loaded, but non-empty dictionary list was provided! (entries: {len(dictionaries)})")
                else:
                    logger.debug("No dictionaries loaded (empty list or None provided).")
                return True
            else:
                logger.debug(f"Loaded {len(dictionaries)} dictionary entries into LibFuzzer")
                return True
        except Exception as e:
            logger.error(f"Exception loading dictionaries: {e}")
            return False
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data using libFuzzer"""
        if not self.is_libfuzzer_available():
            raise RuntimeError("LibFuzzer C extension is not available. Please compile and install the extension.")
        return self._mutate_with_libfuzzer(data, dictionaries)

    def _mutate_with_libfuzzer(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Perform mutation using the libFuzzer C extension with hybrid dictionary support"""
        if not data:
            return data
        
        # Prepare input data
        input_size = len(data)
        input_data = (ctypes.c_uint8 * input_size)(*data)
        
        # Prepare output buffer (make it larger to allow for expansions)
        max_output_size = max(input_size * DEFAULT_OUTPUT_BUFFER_MULTIPLIER, DEFAULT_MAX_OUTPUT_SIZE)
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
        """Ensure dictionaries are loaded into LibFuzzer's native dictionary system"""
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
                     current_value: Any,
                     dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None,
                     layer: Optional[Any] = None) -> Any:
        # If libfuzzer is not available, return current value to allow manager to try other mutators
        if not self.is_libfuzzer_available():
            return current_value

        kind = getattr(field_info, 'kind', 'unknown')

        # Helper: mutate some bytes, return bytes
        def mutate_bytes_seed(b: bytes) -> bytes:
            try:
                return self.mutate_bytes(b, dictionaries)
            except Exception:
                return b

        # Helper: parse int from bytes/str
        def parse_int(data: bytes | str) -> Optional[int]:
            try:
                s = data.decode('utf-8', errors='ignore') if isinstance(data, (bytes, bytearray)) else str(data)
                m = re.search(r"([+-]?0x[0-9a-fA-F]+|[+-]?\d+)", s)
                if not m:
                    return None
                token = m.group(1)
                base = 16 if token.lower().startswith('0x') else 10
                return int(token, base)
            except Exception:
                return None

        # Helper: clamp
        def clamp(v: int, mn: Optional[int], mx: Optional[int]) -> int:
            if mn is not None and v < mn:
                v = mn
            if mx is not None and v > mx:
                v = mx
            return v

        if kind in ('numeric', 'flags', 'enum'):
            seed = ("" if current_value is None else str(current_value)).encode('utf-8', errors='ignore')
            mutated = mutate_bytes_seed(seed)
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
                        try:
                            val = allowed_ints[val % len(allowed_ints)]
                        except Exception:
                            pass
            return val

        if kind == 'string':
            # If current value is None/empty, use a dictionary entry as seed
            if current_value is None or str(current_value).strip() == "":
                if dictionaries and len(dictionaries) > 0:
                    # Use a random dictionary entry as seed
                    import random
                    random_dict_entry = random.choice(dictionaries)
                    if isinstance(random_dict_entry, bytes):
                        seed = random_dict_entry
                    else:
                        seed = str(random_dict_entry).encode('utf-8', errors='ignore')
                else:
                    # Fallback: use a small default seed instead of empty
                    seed = b"test"
            else:
                seed = str(current_value).encode('utf-8', errors='ignore')
            
            mutated = mutate_bytes_seed(seed)
            try:
                s = mutated.decode('utf-8', errors='ignore')
            except Exception:
                s = mutated.decode('latin-1', errors='ignore')
            max_len = getattr(field_info, 'max_length', None)
            if isinstance(max_len, int) and max_len > 0:
                s = s[:max_len]
            return s

        if kind in ('options', 'list'):
            # Let the manager/scapy mutator handle options
            return None

        if kind == 'raw':
            seed = b"" if current_value is None else (current_value if isinstance(current_value, (bytes, bytearray)) else str(current_value).encode('utf-8', errors='ignore'))
            return mutate_bytes_seed(seed)

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
                    logger.debug(f"Initialized LibFuzzer with {len(dictionaries)} dictionary entries")
                return success
            except Exception as e:
                logger.warning(f"Failed to initialize LibFuzzer with dictionaries: {e}")
                return False
        
        return True
            

    
    def _bytes_to_field_value(self, data: bytes, field_info: Any) -> Any:
        """Convert mutated bytes back to appropriate field value based on field type."""
        kind = getattr(field_info, 'kind', 'unknown')
        
        if kind in ('numeric', 'flags', 'enum'):
            try:
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
            except Exception:
                pass
            return 0
            
        elif kind == 'string':
            try:
                s = data.decode('utf-8', errors='ignore')
                max_len = getattr(field_info, 'max_length', None)
                if isinstance(max_len, int) and max_len > 0:
                    s = s[:max_len]
                return s
            except Exception:
                return ""
                
        elif kind == 'raw':
            return data
            
        else:
            # For unknown kinds, try to return as string
            try:
                return data.decode('utf-8', errors='ignore')
            except Exception:
                return data
    
    def teardown(self) -> bool:
        """Clean up LibFuzzer resources."""
        self._dictionaries_loaded = False
        return True
