"""
ScapyMutator: Proper Scapy field-level fuzzing using field.randval() method.
"""

import logging
import random
from typing import Any, List, Optional

from scapy.packet import Packet, fuzz

from .base import BaseMutator, MutatorRegistry
logger = logging.getLogger(__name__)

class ScapyMutator(BaseMutator):
    """Mutator that uses proper Scapy field randomization logic for field-level fuzzing."""
    
    def mutate_bytes(self, data: bytes, dictionary_entries=None) -> bytes:
        """Return input data unchanged since byte mutation is not meaningful for Scapy fuzz."""
        logger.debug("ScapyMutator.mutate_bytes called - returning unchanged data")
        return data

    def mutate_field(self, field_info: Any, dictionaries: Optional[List[bytes]] = None, rng: Optional[random.Random] = None, layer: Optional[Any] = None) -> Any:
        """
        Mutate field using Scapy's field randomization logic.
        
        This mutator requires layer context to use Scapy's field.randval() method.
        If no layer is provided, it returns None to indicate mutation failure,
        allowing the retry logic to attempt other mutators.
        
        Args:
            field_info: Field information with field_name and current_value
            dictionaries: Dictionary entries (unused by this mutator)
            rng: Random number generator (unused)
            layer: Scapy packet layer containing the field (required)
            
        Returns:
            Properly fuzzed field value using Scapy's randomization logic, or None if failed
        """
        field_name = getattr(field_info, 'field_name', 'unknown')
        current_value = getattr(field_info, 'current_value', None)
        
        logger.debug(f"ScapyMutator.mutate_field: field={field_name}, current_value={current_value}, has_layer={layer is not None}")
        
        # ScapyMutator requires layer context for proper Scapy field randomization
        if layer is None:
            logger.debug(f"ScapyMutator: No layer provided for field '{field_name}' - mutation failed")
            return None
            
        if not field_name or field_name == 'unknown':
            logger.warning(f"ScapyMutator: Invalid field_name: {field_name}")
            return None
            
        field_obj = layer.get_field(field_name)
        if field_obj is None:
            logger.warning(f"ScapyMutator: Field '{field_name}' not found in layer {type(layer).__name__}")
            return None
            
        if not hasattr(field_obj, 'randval'):
            logger.warning(f"ScapyMutator: Field '{field_name}' ({type(field_obj).__name__}) has no randval() method")
            return None
            
        try:
            rand_val = field_obj.randval()
            if rand_val is None:
                logger.warning(f"ScapyMutator: Field '{field_name}' randval() returned None")
                return None
                
            if hasattr(rand_val, '_fix'):
                mutated_value = rand_val._fix()
                logger.debug(f"ScapyMutator: Successfully mutated {field_name}: {current_value} -> {mutated_value} (via randval()._fix())")
                return mutated_value
            else:
                logger.debug(f"ScapyMutator: Successfully mutated {field_name}: {current_value} -> {rand_val} (direct randval())")
                return rand_val
        except Exception as e:
            logger.debug(f"ScapyMutator: randval() failed for field '{field_name}': {e}")
            return None


MutatorRegistry.register("scapy", ScapyMutator)