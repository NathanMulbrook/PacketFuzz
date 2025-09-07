"""
ScapyMutator: Proper Scapy field-level fuzzing using field.randval() method.
"""

# Standard library imports
import logging
import random
from typing import Any, List, Optional

# Third-party imports
from scapy.packet import Packet, fuzz

# Local imports
from .base import BaseMutator, MutatorRegistry

# Configure logger for this module
logger = logging.getLogger(__name__)

class ScapyMutator(BaseMutator):
    """Mutator that uses proper Scapy field randomization logic for field-level fuzzing."""
    
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        """Return input data unchanged since byte mutation is not meaningful for Scapy fuzz."""
        logger.debug("ScapyMutator.mutate_bytes called - returning unchanged data")
        # Not meaningful for raw bytes, so just return the input
        return data

    def mutate_field(self, field_info: Any, dictionaries: Optional[List[bytes]] = None, rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """
        Mutate field using proper Scapy field randomization logic.
        
        This implementation uses Scapy's field.randval()._fix() method to generate
        field-appropriate random values that respect field constraints, types, and 
        protocol-specific logic. This is the core mechanism that Scapy's fuzz() 
        function uses internally.
        
        Args:
            field_info: Field information with field_name and current_value
            dictionaries: Dictionary entries (unused by this mutator)
            rng: Random number generator for fallback strategies
            layer: Scapy packet layer containing the field
            
        Returns:
            Properly fuzzed field value using Scapy's randomization logic
        """
        field_name = getattr(field_info, 'field_name', 'unknown')
        current_value = getattr(field_info, 'current_value', None)
        
        logger.debug(f"ScapyMutator.mutate_field: field={field_name}, current_value={current_value}, has_layer={layer is not None}")
        
        # Primary strategy: Use Scapy's field-specific randomization
        if layer is not None:
            if field_name and field_name != 'unknown':
                # Get the actual Scapy field object from the layer
                field_obj = layer.get_field(field_name)
                
                if field_obj is None:
                    logger.warning(f"ScapyMutator: Field '{field_name}' not found in layer {type(layer).__name__}")
                elif not hasattr(field_obj, 'randval'):
                    logger.warning(f"ScapyMutator: Field '{field_name}' ({type(field_obj).__name__}) has no randval() method")
                else:
                    try:
                        rand_val = field_obj.randval()
                        if rand_val is None:
                            logger.warning(f"ScapyMutator: Field '{field_name}' randval() returned None")
                        else:
                            # Fix volatile values to get concrete random data
                            if hasattr(rand_val, '_fix'):
                                mutated_value = rand_val._fix()
                                logger.debug(f"ScapyMutator: Successfully mutated {field_name}: {current_value} -> {mutated_value} (via randval()._fix())")
                                return mutated_value
                            else:
                                logger.debug(f"ScapyMutator: Successfully mutated {field_name}: {current_value} -> {rand_val} (direct randval())")
                                return rand_val
                    except Exception as e:
                        logger.debug(f"ScapyMutator: randval() failed for field '{field_name}': {e}")
                        # Don't catch this - let the caller handle the failure
                        raise
            else:
                logger.warning(f"ScapyMutator: Invalid field_name: {field_name}")
                
        else:
            logger.debug(f"ScapyMutator: No layer provided for field '{field_name}', using fallback")
        
        # Fallback strategies for edge cases or when layer is not available
        logger.debug(f"ScapyMutator: Using fallback mutation for field '{field_name}'")
        return self._fallback_mutation(field_info, rng)
    
    def _fallback_mutation(self, field_info: Any, rng: Optional[random.Random] = None) -> Any:
        """
        Fallback mutation strategies when Scapy field randomization is not available.
        
        These strategies are used as backup when the primary Scapy field.randval() 
        approach fails or when layer context is not available.
        """
        if rng is None:
            rng = random.Random()
            
        field_name = getattr(field_info, 'field_name', 'unknown')
        kind = getattr(field_info, 'kind', None) or getattr(field_info, 'field_kind', 'unknown')
        current_value = getattr(field_info, 'current_value', None)
        
        logger.debug(f"ScapyMutator: Fallback mutation for field '{field_name}', kind='{kind}', current_value={current_value}")
        
        if kind in ('options', 'list'):
            # Return current_value as-is for complex field types
            logger.debug(f"ScapyMutator: Fallback for complex field type '{kind}', returning unchanged")
            return current_value
            
        elif kind in ('string', 'raw'):
                # String/raw field fallback strategies
                s = '' if current_value is None else str(current_value)
                if len(s) == 0:
                    # Generate random string for empty values
                    mutated_value = ''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=rng.randint(1, 16)))
                    logger.debug(f"ScapyMutator: Fallback string generation: '' -> '{mutated_value}'")
                    return mutated_value
                elif len(s) < 256:
                    # For short strings, try various mutations
                    strategy = rng.randint(1, 4)
                    if strategy == 1:
                        mutated_value = s + chr(rng.randint(32, 126))  # Append random printable char
                        logger.debug(f"ScapyMutator: Fallback string append: '{s}' -> '{mutated_value}'")
                        return mutated_value
                    elif strategy == 2:
                        mutated_value = chr(rng.randint(0, 255)) + s  # Prepend random byte
                        logger.debug(f"ScapyMutator: Fallback string prepend: '{s}' -> '{mutated_value}'")
                        return mutated_value
                    elif strategy == 3 and len(s) > 1:
                        idx = rng.randint(0, len(s)-1)
                        mutated_value = s[:idx] + chr(rng.randint(0, 255)) + s[idx+1:]  # Replace random char
                        logger.debug(f"ScapyMutator: Fallback string replace: '{s}' -> '{mutated_value}'")
                        return mutated_value
                    else:
                        mutated_value = s * rng.randint(2, 4)  # Duplicate string
                        logger.debug(f"ScapyMutator: Fallback string duplicate: '{s}' -> '{mutated_value}'")
                        return mutated_value
                else:
                    logger.debug(f"ScapyMutator: Fallback large string unchanged: '{s[:50]}...'")
                    return s  # Return large strings unchanged
                    
        else:
            # Numeric, flags, enum, or unknown field fallback strategies
            v = 0 if current_value is None else current_value
            int_val = int(v)
            # Multiple numeric mutation strategies
            strategy = rng.randint(1, 6)
            if strategy == 1:
                mutated_value = int_val ^ rng.randint(1, 0xFFFF)  # XOR with random value
                logger.debug(f"ScapyMutator: Fallback XOR mutation: {int_val} -> {mutated_value}")
                return mutated_value
            elif strategy == 2:
                mutated_value = rng.randint(0, 65535)  # Random replacement
                logger.debug(f"ScapyMutator: Fallback random replacement: {int_val} -> {mutated_value}")
                return mutated_value
            elif strategy == 3:
                delta = rng.randint(-1000, 1000)
                mutated_value = int_val + delta  # Arithmetic mutation
                logger.debug(f"ScapyMutator: Fallback arithmetic mutation: {int_val} + {delta} = {mutated_value}")
                return mutated_value
            elif strategy == 4:
                shift = rng.randint(1, 4)
                mutated_value = int_val << shift  # Bit shift
                logger.debug(f"ScapyMutator: Fallback bit shift: {int_val} << {shift} = {mutated_value}")
                return mutated_value
            elif strategy == 5:
                or_val = rng.randint(1, 0xFF)
                mutated_value = int_val | or_val  # OR with random value
                logger.debug(f"ScapyMutator: Fallback OR mutation: {int_val} | {or_val} = {mutated_value}")
                return mutated_value
            else:
                # Boundary values
                boundaries = [0, 1, 255, 256, 65535, 65536]
                mutated_value = rng.choice(boundaries)
                logger.debug(f"ScapyMutator: Fallback boundary value: {int_val} -> {mutated_value}")
                return mutated_value


# Register this mutator
# Removed manual registration - now uses auto-discovery
