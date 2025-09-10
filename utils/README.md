# Dictionary Analysis Utilities

This folder contains standalone utilities for analyzing PacketFuzz dictionary mappings.

## Available Tools

### 1. Dictionary Resolver (`dictionary_resolver.py`)
**Full analysis and resolution of all dictionary mappings**

```bash
python utils/dictionary_resolver.py
```

**Features:**
- Resolves all macros and expands dependencies
- Generates complete dictionary files for each mapping
- Creates detailed JSON analysis files
- Outputs human-readable summary reports
- Identifies missing dictionary files
- Handles circular dependency detection

**Output Location:** `artifacts/dictionary_analysis/`

**Generated Files:**
- `dictionary_summary_TIMESTAMP.txt` - Human-readable overview
- `macro_analysis_TIMESTAMP.json` - Detailed macro breakdown
- `field_type_analysis_TIMESTAMP.json` - Field type mappings
- `field_name_analysis_TIMESTAMP.json` - Field name mappings  
- `field_advanced_analysis_TIMESTAMP.json` - Advanced mappings
- `resolved_dictionaries_TIMESTAMP/` - Individual resolved dictionary files
  - `macros/` - Each macro as a separate file
  - `field_types/` - Field type dictionaries
  - `field_names/` - Field name dictionaries

### 2. Dictionary Stats (`dictionary_stats.py`)
**Quick statistics without full file generation**

```bash
python utils/dictionary_stats.py
```

**Features:**
- Fast overview of macro statistics
- File usage frequency analysis
- Dependency relationship mapping
- Entry count estimates
- No file generation (quick execution)

## Understanding the Output

### Macro Dependencies
Macros can reference other macros using `@macro_name` syntax. The tools will:
- Resolve all dependencies recursively
- Detect circular references
- Show dependency trees in the analysis

### Entry Counts
- **Raw counts**: Number of lines in source files
- **Resolved counts**: After macro expansion and deduplication
- **Missing files**: Files referenced but not found

### Field Mappings
Three types of field mappings are analyzed:
- **Type-based**: Maps Scapy field types to dictionaries
- **Name-based**: Maps specific field names to dictionaries  
- **Advanced**: Override mappings (currently empty)

## Example Usage

### Quick Check
```bash
# Get a quick overview
python utils/dictionary_stats.py
```

### Full Analysis
```bash
# Generate complete analysis
python utils/dictionary_resolver.py

# View the summary
cat artifacts/dictionary_analysis/dictionary_summary_*.txt

# Check resolved XSS payloads
cat artifacts/dictionary_analysis/resolved_dictionaries_*/macros/macro_xss.txt
```

### Inspecting Specific Mappings
```bash
# View what gets applied to MySQL query fields
cat artifacts/dictionary_analysis/resolved_dictionaries_*/field_names/name_MySQL_query.txt

# Check numeric fuzzing values
cat artifacts/dictionary_analysis/resolved_dictionaries_*/macros/macro_enhanced_numeric.txt
```

## Integration Notes

These utilities are **standalone** and do not integrate with PacketFuzz itself. They are designed for:
- Dictionary mapping validation
- Content inspection and auditing
- Performance impact assessment  
- Security research and development

The tools read from `packetfuzz/default_mappings.py` but do not modify it or affect runtime behavior.
