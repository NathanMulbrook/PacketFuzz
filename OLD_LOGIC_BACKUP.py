# Backup of removed _fuzz_field_in_layer logic for comparison

# This is what was removed from the old system:

def _fuzz_field_in_layer(self, layers: List[Any], field_desc, fname: str, merged_field_mapping: Optional[List[dict]] = None, force_fuzz: bool = False) -> List[int]:
    """
    Fuzz a specific field across multiple layers (batch processing) with dictionary and mutation support.
    
    Key features that were in the old system:
    1. Batch processing across multiple layers
    2. FuzzField configuration extraction
    3. Campaign defaults from merged_field_mapping
    4. Explicit values handling
    5. Dictionary integration 
    6. Weight-based skipping
    7. Retry logic with multiple mutators
    8. Comprehensive validation and assignment
    9. FuzzField wrapper removal
    10. Fallback to different mutation strategies
    
    Returns:
        List of indexes (0-based) of layers that were NOT fuzzed
    """
    
    # Key functionality that was in old system:
    # - Extract campaign defaults from merged_field_mapping
    # - Extract FuzzField configuration with campaign-level defaults  
    # - Type-aware mutation using FieldInfo + mutate_field API
    # - Extract explicit values with dictionary merging
    # - Remove FuzzField wrappers from all layers
    # - Apply explicit values to all layers with validation
    # - Mutator-based generation with retries
    # - Weight checking per layer
    # - Multiple mutation attempts with fallback
    # - Comprehensive field validation and assignment
    # - Error handling and tracking
    
    pass

# Key methods that were removed:
# - _build_field_info() - Built FieldInfo from Scapy field descriptors  
# - _select_mutator_for_field() - Selected appropriate mutator
# - _mutate_with_retries() - Retry logic with multiple attempts
# - _validate_and_assign() - Field validation and assignment
