

## Dictionary Management

### Hierarchy & Resolution

The framework uses a 3-tier hierarchical system for dictionary resolution with sophisticated merging:

.. mermaid::
flowchart TD
    A[Field Needs Dictionary] --> B{FuzzField Has<br/>Dictionaries?}
    B -->|Yes| C[Use FuzzField<br/>Dictionaries<br/>Priority: 1 Highest]
    B -->|No| D{Campaign/CLI<br/>Override Exists?}
    D -->|Yes| E[Use Campaign/CLI<br/>Configuration<br/>Priority: 2 Medium]
    D -->|No| F[Use Default<br/>Mappings<br/>Priority: 3 Lowest]
    
    C --> G{Override Flag<br/>Set?}
    E --> G
    F --> G
    
    G -->|Yes| H[Use Only This Source<br/>No Merging]
    G -->|No| I[Merge All Available<br/>Sources]
    
    H --> J[Apply Weight Resolution]
    I --> J
    J --> K[Final Dictionary List<br/>& Field Weights]
    
    style C fill:#c8e6c9
    style E fill:#fff3e0
    style F fill:#f3e5f5
    style K fill:#e3f2fd
```

**Key Features:**
- Hierarchical merging with override controls
- Field-specific and pattern-based mappings
- Weight resolution for mutation prioritization
- CLI and campaign-level configuration overrides

**Implementation**: `packetfuzz.dictionary_manager.DictionaryManager`
**Configuration**: `packetfuzz.default_mappings`
**Examples**: `examples/config/user_dictionary_config.py`



### Dictionary Sources & Priority

| Priority | Source | Scope | Override Control | Example |
|----------|--------|-------|------------------|---------|
| **1** | FuzzField | Single field | Not applicable | `FuzzField(dictionaries=["custom.txt"])` |
| **2** | Campaign Config | Campaign-wide | `dictionary_override` flag | `dictionary_config_file = "config.py"` |
| **3** | CLI Override | Global | Command-line flag | `--dictionary-config config.py` |
| **4** | Default Mappings | Framework | Built-in rules | Automatic field associations |

- All dictionaries are merged unless `dictionary_override=True` is set for a field in user/campaign/CLI config.
- Inline FuzzField dictionaries always take precedence and are never overridden.

### Configuration Examples

**Default Mappings**: Built-in field-to-dictionary associations in `packetfuzz/default_mappings.py`
**User Configuration**: Campaign and CLI overrides in `examples/config/user_dictionary_config.py`
**CLI Usage**: Global dictionary overrides via `--dictionary-config` flag

**Detailed Examples**: 
- Basic configuration: `examples/intermediate/02_dictionary_config.py`
- Configuration files: `examples/config/user_dictionary_config.py`
