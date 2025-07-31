"""
libFuzzer integration module

This module provides the interface to the libFuzzer C extension
for high-performance mutation operations.
"""

import ctypes
import logging
import random
import shutil
import os
from pathlib import Path
from typing import List, Optional, Any
from scapy.fields import Field

from .base import BaseMutator

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MAX_OUTPUT_SIZE = 1024
DEFAULT_OUTPUT_BUFFER_MULTIPLIER = 2


class LibFuzzerMutator(BaseMutator):
    """
    libFuzzer-based mutator using the C extension
    
    Provides high-performance mutations using libFuzzer's proven algorithms.
    Requires the C extension to be compiled and available.
    """
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._seed = seed
        self._lib = None
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
            logger.error("Could not load libFuzzer extension: %s", e)
            raise RuntimeError("LibFuzzer extension failed to load. Check compilation.")
    
    def _find_library_path(self) -> Optional[str]:
        """Find the compiled libFuzzer extension library (Linux only)"""
        current_dir = Path(__file__).resolve().parent
        # Only Linux is currently supported
        linux_lib = 'libscapy_libfuzzer.so'
        path = current_dir / linux_lib
        if path.exists():
            return str(path)
        return None
    
    def _setup_function_signatures(self):
        """Setup ctypes function signatures for the C library"""
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

    def load_dictionaries_for_native_support(self, dictionaries: List[str], corpus_dir: Optional[str] = None) -> bool:
        """
        Load dictionaries into LibFuzzer and generate a seed corpus.
        Args:
            dictionaries: List of dictionary strings to load
            corpus_dir: Optional path to the corpus directory for seed files
        Returns:
            True if loaded or no dictionaries to load, False if error
        """
        # Ensure the LibFuzzer C extension library is loaded before proceeding
        if not self._lib:
            return False
        if not dictionaries:
            logger.info("No dictionaries provided to load; skipping dictionary loading.")
            return True
        try:
            # Convert to C format
            dict_entries = (ctypes.c_char_p * len(dictionaries))()
            for i, entry in enumerate(dictionaries):
                dict_entries[i] = ctypes.c_char_p(entry.encode('utf-8', errors='ignore'))
            # Load into LibFuzzer
            result = self._lib.load_dictionaries_native(dict_entries, len(dictionaries))
            # Always generate a seed corpus if corpus_dir is provided
            if corpus_dir is not None:
                self.generate_dictionary_seed(dictionaries, corpus_dir)
            elif os.environ.get("SCAPY_LIBFUZZER_CORPUS"):
                self.generate_dictionary_seed(dictionaries, os.environ["SCAPY_LIBFUZZER_CORPUS"])
            if result == -1:
                logger.error("Error loading dictionaries: allocation or internal error.")
                return False
            elif result == 0:
                if dictionaries:
                    logger.error("No dictionaries loaded, but non-empty dictionary list was provided! (entries: %d)", len(dictionaries))
                else:
                    logger.info("No dictionaries loaded (empty list or None provided).")
                return True
            else:
                logger.info(f"Loaded {len(dictionaries)} dictionary entries into LibFuzzer")
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

    def generate_dictionary_seed(self, dictionaries: List[str], corpus_dir: str, max_size: int = DEFAULT_MAX_OUTPUT_SIZE) -> None:
        """
        Create/clean the corpus directory and seed it with all dictionary values as files.
        Args:
            dictionaries: List of dictionary strings to seed
            corpus_dir: Path to the corpus directory
            max_size: Maximum size of each seed file
        """
        corpus_path = Path(corpus_dir)
        # Create or clean the corpus directory
        if corpus_path.exists():
            for file_path in corpus_path.iterdir():
                if file_path.is_file():
                    file_path.unlink()
        else:
            corpus_path.mkdir(parents=True, exist_ok=True)
        # Write each dictionary value to a separate file
        for idx, value in enumerate(dictionaries):
            file_path = corpus_path / f"seed_{idx}.bin"
            with open(file_path, "wb") as f:
                f.write(value.encode('utf-8', errors='ignore')[:max_size])
    
    def is_libfuzzer_available(self) -> bool:
        """Check if the LibFuzzer C extension is available and loaded."""
        return self._lib is not None
