# Dictionary Fallback Configuration Enhancement

## Problem Statement

Currently, when fields don't have dictionary mappings, the `DictionaryOnlyMutator` returns empty strings, leading to ineffective fuzzing. This document outlines the implementation of a configurable fallback system for dictionary-only mutation scenarios.

## Current Behavior

```python
# In DictionaryOnlyMutator.mutate_field()
if not dictionaries:
    return ""  # Always returns empty string
```

## Proposed Solution

### Configuration Constant

Add a new configuration constant to control fallback behavior when no dictionaries are available:

```python
# In packetfuzz/default_mappings.py or new config module

# Dictionary-only mutator fallback modes
DICTIONARY_ONLY_FALLBACK_MODE = "empty"  # Default: maintain current behavior

# Supported modes:
# "empty"     - Return empty string (current behavior)
# "original"  - Return original field value unchanged  
# "generic"   - Use generic string/numeric values based on field type
# "skip"      - Skip mutation entirely (return None to indicate skip)
```

### Implementation Changes

#### 1. Enhanced DictionaryOnlyMutator

```python
# In packetfuzz/mutators/dictionary_only_mutator.py

def mutate_field(self, field_value, field_name, field_type, dictionaries, field_info=None):
    """Mutate field using only dictionary entries with configurable fallback."""
    
    if dictionaries:
        # Existing dictionary-based mutation logic
        return self._pick_entry(dictionaries, field_info)
    
    # Handle fallback based on configuration
    fallback_mode = getattr(config, 'DICTIONARY_ONLY_FALLBACK_MODE', 'empty')
    
    if fallback_mode == "empty":
        return ""
    elif fallback_mode == "original":
        return field_value
    elif fallback_mode == "generic":
        return self._get_generic_value(field_type, field_value)
    elif fallback_mode == "skip":
        return None  # Indicates mutation should be skipped
    else:
        # Unknown mode, fall back to default
        return ""

def _get_generic_value(self, field_type, original_value):
    """Generate generic values based on field type."""
    generic_values = {
        'StrField': ['test', 'admin', 'null', ''],
        'XStrField': ['test', 'admin', 'null', ''],
        'IntField': [0, 1, -1, 65535, 2147483647],
        'ShortField': [0, 1, -1, 65535],
        'ByteField': [0, 1, 255],
        'BitField': [0, 1],
        # Legacy support for generic types
        'string': ['test', 'admin', 'null', ''],
        'numeric': [0, 1, -1, 65535],
    }
    
    values = generic_values.get(field_type, ['test'])
    return random.choice(values)
```

#### 2. Simple Configuration

```python
# In packetfuzz/default_mappings.py - add at top

# Dictionary fallback configuration
DICTIONARY_ONLY_FALLBACK_MODE = "empty"  # Default: maintain current behavior

# Supported modes:
# "empty"     - Return empty string (current behavior)
# "original"  - Return original field value unchanged  
# "generic"   - Use generic string/numeric values based on field type
# "skip"      - Skip mutation entirely (return None to indicate skip)
```

#### 3. CLI Integration (Optional)

```python
# In packetfuzz/cli.py - add new command line option if desired

parser.add_argument(
    '--dictionary-fallback',
    choices=['empty', 'original', 'generic', 'skip'],
    default='empty',
    help='Fallback behavior when no dictionaries are available for a field'
)

# In main() function - set the global variable
if args.dictionary_fallback:
    import packetfuzz.default_mappings as config
    config.DICTIONARY_ONLY_FALLBACK_MODE = args.dictionary_fallback
```

### Usage Examples

#### Command Line Usage

```bash
# Use original values when no dictionaries available
python -m packetfuzz input.pcap --dictionary-fallback original

# Use generic values based on field type
python -m packetfuzz input.pcap --dictionary-fallback generic

# Skip fields without dictionaries entirely
python -m packetfuzz input.pcap --dictionary-fallback skip
```

#### Programmatic Usage

```python
# Set fallback mode before running fuzzer
import packetfuzz.default_mappings as config
config.DICTIONARY_ONLY_FALLBACK_MODE = "generic"

# Run fuzzing with enhanced fallback
fuzzer.fuzz_file("input.pcap")
```

### Testing Strategy

#### Unit Tests

1. Test each fallback mode with various field types
2. Test configuration validation and error handling
3. Test CLI argument parsing and integration

#### Integration Tests

1. Test end-to-end fuzzing with different fallback modes
2. Verify PCAP output contains expected mutations
3. Performance testing with large datasets

### Backward Compatibility

- Default mode remains "empty" to maintain current behavior
- Existing code continues to work without changes
- Configuration is opt-in through CLI or programmatic interface

### Benefits

1. **Flexibility**: Users can choose appropriate fallback behavior for their use case
2. **Better Coverage**: Fields without dictionaries can still be meaningfully fuzzed
3. **Debugging**: "original" mode helps identify which fields lack proper dictionary mappings
4. **Performance**: "skip" mode can improve performance by avoiding unnecessary mutations

### Implementation Priority

**Phase 1**: Add configuration constant to `default_mappings.py`
**Phase 2**: Update `DictionaryOnlyMutator.mutate_field()` method  
**Phase 3**: Add CLI integration (optional)
**Phase 4**: Testing and documentation
