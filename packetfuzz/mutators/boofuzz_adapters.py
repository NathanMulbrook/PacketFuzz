"""
Boofuzz Adapter Classes

Provides adapter classes that wrap boofuzz primitives to work with PacketFuzz's BaseMutator interface.
Each adapter class handles the interface translation between PacketFuzz and boofuzz.
"""

import logging
import random
from typing import Any, List, Optional

from scapy.fields import Field
from scapy.packet import Packet

from .base import BaseMutator
from ..mutator_manager_data import FieldMetadata
from .boofuzz.primitives import (
    Bytes, String, Byte, Word, DWord, QWord, Float, BitField, Static, Delim, RandomData
)

logger = logging.getLogger(__name__)


class BoofuzzBytesAdapter(BaseMutator):
    """Adapter for boofuzz Bytes primitive"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._primitive = None
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_bytes"
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data using boofuzz Bytes primitive"""
        if self._primitive is None:
            self._primitive = Bytes(default_value=data)
        
        # Use mutations() method which returns the actual mutation values
        mutations = list(self._primitive.mutations(data))
        if not mutations:
            return data
            
        # Randomly select a mutation
        mutation = random.choice(mutations)
        
        # If mutation is callable, apply it to the data
        if callable(mutation):
            result = mutation(data)
        else:
            result = mutation
            
        return result if isinstance(result, bytes) else data
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """Mutate field using boofuzz Bytes primitive"""
        current_value = field_info.current_value
        if isinstance(current_value, bytes):
            return self.mutate_bytes(current_value, dictionaries)
        elif isinstance(current_value, str):
            mutated_bytes = self.mutate_bytes(current_value.encode('utf-8', errors='ignore'), dictionaries)
            return mutated_bytes.decode('utf-8', errors='ignore')
        else:
            # Convert to bytes, mutate, then try to convert back
            data_bytes = str(current_value).encode('utf-8', errors='ignore')
            return self.mutate_bytes(data_bytes, dictionaries)


class BoofuzzStringAdapter(BaseMutator):
    """Adapter for boofuzz String primitive"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._primitive = None
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_string"
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data by converting to string first"""
        string_data = data.decode('utf-8', errors='ignore')
        if self._primitive is None:
            self._primitive = String(default_value=string_data)
        
        # Use mutations() method which returns the actual mutation values
        mutations = list(self._primitive.mutations(string_data))
        if not mutations:
            return data
            
        # Randomly select a mutation
        mutation = random.choice(mutations)
        
        # If mutation is callable, apply it to the data
        if callable(mutation):
            result = mutation(string_data)
        else:
            result = mutation
            
        # Convert string result back to bytes
        return result.encode('utf-8', errors='ignore') if isinstance(result, str) else data
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """Mutate field using boofuzz String primitive"""
        current_value = field_info.current_value
        if isinstance(current_value, str):
            if self._primitive is None:
                self._primitive = String(default_value=current_value)
            
            # Use mutations() method which returns the actual mutation values
            mutations = list(self._primitive.mutations(current_value))
            if mutations:
                # Randomly select a mutation
                mutation = random.choice(mutations)
                
                # If mutation is callable, apply it to the data
                if callable(mutation):
                    result = mutation(current_value)
                else:
                    result = mutation
                    
                return result if isinstance(result, str) else current_value
        elif isinstance(current_value, bytes):
            mutated_bytes = self.mutate_bytes(current_value, dictionaries)
            return mutated_bytes.decode('utf-8', errors='ignore')
        
        return current_value


class BoofuzzIntegerAdapter(BaseMutator):
    """Base adapter for integer-based boofuzz primitives"""
    
    def __init__(self, primitive_class, seed: Optional[int] = None):
        super().__init__(seed)
        self._primitive_class = primitive_class
        self._primitive = None
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data by interpreting as integer"""
        # Try to interpret bytes as integer
        try:
            if len(data) == 1:
                int_val = int.from_bytes(data, 'little')
            elif len(data) == 2:
                int_val = int.from_bytes(data, 'little')
            elif len(data) == 4:
                int_val = int.from_bytes(data, 'little')
            elif len(data) == 8:
                int_val = int.from_bytes(data, 'little')
            else:
                int_val = 0
        except (ValueError, OverflowError) as e:
            logger.warning(f"Failed to convert bytes to int: {data.hex()}: {e}")
            int_val = 0
        
        if self._primitive is None:
            self._primitive = self._primitive_class(default_value=int_val)
        
        # Use mutations() method which returns the actual mutation values
        mutations = list(self._primitive.mutations(int_val))
        if mutations:
            # Randomly select a mutation
            mutation = random.choice(mutations)
            
            # If mutation is callable, apply it to the data
            if callable(mutation):
                result = mutation(int_val)
            else:
                result = mutation
                
            # Convert result back to bytes with appropriate length
            try:
                if isinstance(result, int):
                    return result.to_bytes(len(data), 'little')
                else:
                    return data
            except (ValueError, OverflowError) as e:
                logger.warning(f"Failed to convert int {result} to bytes (length {len(data)}): {e}")
                return data
        return data
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """Mutate field using boofuzz integer primitive"""
        current_value = field_info.current_value
        
        # Handle integer values directly
        if isinstance(current_value, int):
            if self._primitive is None:
                self._primitive = self._primitive_class(default_value=current_value)
            
            # Use mutations() method which returns the actual mutation values
            mutations = list(self._primitive.mutations(current_value))
            if mutations:
                # Randomly select a mutation
                mutation = random.choice(mutations)
                
                # If mutation is callable, apply it to the data
                if callable(mutation):
                    result = mutation(current_value)
                else:
                    result = mutation
                    
                # Return the integer result
                return result if isinstance(result, int) else current_value
        
        # Handle bytes
        elif isinstance(current_value, bytes):
            mutated_bytes = self.mutate_bytes(current_value, dictionaries)
            # Try to convert back to appropriate integer size
            try:
                return int.from_bytes(mutated_bytes[:len(current_value)], 'little')
            except (ValueError, OverflowError) as e:
                logger.warning(f"Failed to convert mutated bytes back to int: {e}")
                return current_value
        
        return current_value


class BoofuzzByteAdapter(BoofuzzIntegerAdapter):
    """Adapter for boofuzz Byte primitive (8-bit)"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(Byte, seed)
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_byte"


class BoofuzzWordAdapter(BoofuzzIntegerAdapter):
    """Adapter for boofuzz Word primitive (16-bit)"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(Word, seed)
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_word"


class BoofuzzDWordAdapter(BoofuzzIntegerAdapter):
    """Adapter for boofuzz DWord primitive (32-bit)"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(DWord, seed)
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_dword"


class BoofuzzQWordAdapter(BoofuzzIntegerAdapter):
    """Adapter for boofuzz QWord primitive (64-bit)"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(QWord, seed)
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_qword"


class BoofuzzFloatAdapter(BaseMutator):
    """Adapter for boofuzz Float primitive"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._primitive = None
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_float"
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Mutate byte data by interpreting as float"""
        import struct
        try:
            if len(data) >= 4:
                float_val = struct.unpack('<f', data[:4])[0]
            else:
                float_val = 0.0
        except (struct.error, ValueError, TypeError) as e:
            logger.warning(f"Failed to unpack float from data {data[:4].hex()}: {e}")
            float_val = 0.0
        
        if self._primitive is None:
            self._primitive = Float(default_value=float_val)
        
        # Use mutations() method which returns the actual mutation values
        mutations = list(self._primitive.mutations(float_val))
        if mutations:
            # Randomly select a mutation
            mutation = random.choice(mutations)
            
            # Convert string representation to float if needed
            if isinstance(mutation, str):
                try:
                    result = float(mutation)
                except (ValueError, TypeError):
                    result = float_val
            elif callable(mutation):
                result = mutation(float_val)
            else:
                result = mutation
                
            # Convert float result back to bytes
            import struct
            try:
                if isinstance(result, (float, int)):
                    return struct.pack('<f', float(result))
                else:
                    return data
            except (struct.error, ValueError, OverflowError) as e:
                logger.warning(f"Failed to pack float {result}: {e}")
                return data
        return data
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """Mutate field using boofuzz Float primitive"""
        current_value = field_info.current_value
        
        if isinstance(current_value, float):
            if self._primitive is None:
                self._primitive = Float(default_value=current_value)
            
            # Use mutations() method which returns the actual mutation values
            mutations = list(self._primitive.mutations(current_value))
            if mutations:
                # Randomly select a mutation
                mutation = random.choice(mutations)
                
                # Convert string representation to float if needed
                if isinstance(mutation, str):
                    try:
                        result = float(mutation)
                    except (ValueError, TypeError):
                        result = current_value
                elif callable(mutation):
                    result = mutation(current_value)
                else:
                    result = mutation
                    
                return result if isinstance(result, (float, int)) else current_value
        
        return current_value


class BoofuzzRandomDataAdapter(BaseMutator):
    """Adapter for boofuzz RandomData primitive"""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._primitive = None
    
    @classmethod
    def get_name(cls) -> str:
        return "boofuzz_random"
    
    def mutate_bytes(self, data: bytes, dictionaries: Optional[List[bytes]] = None) -> bytes:
        """Generate random data based on input length"""
        if self._primitive is None:
            self._primitive = RandomData(min_length=0, max_length=len(data) * 2)
        
        # Use mutations() method which returns the actual mutation values
        mutations = list(self._primitive.mutations(data))
        if mutations:
            # Randomly select a mutation
            mutation = random.choice(mutations)
            
            # If mutation is callable, apply it to the data
            if callable(mutation):
                result = mutation(data)
            else:
                result = mutation
                
            return result if isinstance(result, bytes) else data
        return data
    
    def mutate_field(self, field_info: FieldMetadata, dictionaries: Optional[List[bytes]] = None,
                     rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """Mutate field using boofuzz RandomData primitive"""
        current_value = field_info.current_value
        
        if isinstance(current_value, bytes):
            return self.mutate_bytes(current_value, dictionaries)
        else:
            # Convert to bytes, mutate, convert back
            data_bytes = str(current_value).encode('utf-8', errors='ignore')
            mutated = self.mutate_bytes(data_bytes, dictionaries)
            if isinstance(current_value, str):
                return mutated.decode('utf-8', errors='ignore')
            else:
                return mutated
