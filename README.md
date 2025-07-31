# PacketFuzz - Advanced Network Protocol Fuzzing Framework

The goal of this project is to combine the mutation capabilities of libfuzzer with the predefined protocols and ease of implenting new protocols in scapy. fuzzdb was added to provide a dictionary dataset to be used murring mutation. This project provides a framework that allows the user to very quickly create high quality protocol fuzzers, but also has the flexability to implement custom protocols, and fuzz stategies when needed. The design of this application attempts to replicate some of the user facing configuration ideas present in scapy.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      SCAPY FUZZING FRAMEWORK                    │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface (scapy_fuzzer_cli.py)                          │
│  ├─ Campaign Discovery & Execution                             │
│  └─ Dictionary Configuration Overrides                        │
├─────────────────────────────────────────────────────────────────┤
│  Campaign Framework (fuzzing_framework.py)                    │
│  ├─ FuzzingCampaign (Base class with inheritance)             │
│  ├─ PcapFuzzCampaign (PCAP-based regression testing)          │
│  ├─ FuzzField (Embedded field configuration)                  │
│  └─ Callback System (5 callback types)                       │
├─────────────────────────────────────────────────────────────────┤
│  Mutator Manager (mutator_manager.py)                         │
│  ├─ Field Discovery & Resolution                              │
│  ├─ Dictionary Integration                                     │
│  └─ Mutation Orchestration                                    │
├─────────────────────────────────────────────────────────────────┤
│  Mutation Engines                                             │
│  ├─ LibFuzzer (C-based binary mutations)                      │
│  ├─ Scapy Native (Built-in fuzz() function)                   │
│  ├─ Dictionary-Only (Exact dictionary values)                 │
│  └─ Python Mutator (Pure Python fallback)                    │
├─────────────────────────────────────────────────────────────────┤
│  Dictionary System                                            │
│  ├─ Default Mappings (Field-to-dictionary mapping)            │
│  ├─ User Overrides (Campaign-specific configs)                │
│  └─ FuzzField Dictionaries (Inline configuration)             │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features

| Feature | Description | Benefits |
|---------|-------------|----------|
| **Campaign Architecture** | Class-based inheritance system | Reusable configurations, organized testing |
| **FuzzField Configuration** | Embed fuzzing params in packet constructors | Clean code, field-level precision |
| **Dictionary Integration** | Hierarchical FuzzDB + custom dictionaries | High-quality payloads, extensible |
| **Multiple Mutation Modes** | LibFuzzer, Scapy, Dictionary-only, Combined | Comprehensive coverage, flexibility |
| **PCAP Integration** | Load/replay captures with fuzzing | Regression testing, real-world scenarios |
| **Callback System** | 5 callback types with full context | Custom logic, monitoring, crash handling |
| **Rate Limiting** | Network-safe packet transmission | Responsible testing, DoS prevention |
| **Protocol Agnostic** | Works with any Scapy packet type | Universal applicability |

---

## Project Structure

```
PacketFuzz/
├── examples/                   # Example scripts and campaign configs
│   ├── basic/                  # Basic examples for beginners
│   ├── advanced/               # Advanced features and patterns
│   ├── demos/                  # Interactive demonstrations
│   └── campaign_examples.py    # Standard campaign configurations
├── tests/                      # Test suite (unit, integration, example validation)
│   └── run_all_tests.py        # Main test runner
├── fuzzdb/                     # FuzzDB dictionary database
├── mutators/                   # Mutation engine components
├── utils/                      # Project utilities
├── fuzzing_framework.py        # Core campaign framework
├── pcapfuzz.py                 # PCAP-based fuzzing
├── default_mappings.py         # Default field-to-dictionary mappings
├── dictionary_manager.py       # Dictionary management and overrides
├── mutator_manager.py          # Core fuzzing engine and Scapy integration
├── scapy_fuzzer_cli.py         # Command-line interface
├── FRAMEWORK_DOCUMENTATION.md  # API and usage documentation
├── requirements.txt            # Python dependencies
└── setup.py                    # Package setup
```

---

## Installation

### Quick Install
```bash
pip install -r requirements.txt
```

### Development Install
```bash
pip install -e .
```

This installs the `scapy-fuzzer` command-line tool.

---

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run tests:**
   ```bash
   python tests/run_all_tests.py
   ```

3. **Try examples:**
   ```bash
   # Basic examples
   python examples/basic/01_quick_start.py
   python examples/basic/02_campaign_types.py
   
   # Run all examples
   python examples/run_all_examples.py
   ```


---

## Usage

### Command-Line Usage

```text
scapy-fuzzer [OPTIONS] <campaign_config.py>
```

**Arguments:**
- `<campaign_config.py>`: Path to your campaign configuration Python file.

**Common Options:**
- `--list-campaigns`    List all campaigns in the config file and exit
- `--dry-run`        Validate campaigns without sending packets
- `--verbose`, `-v`    Enable verbose output
- `--dictionary-config <file.py>` Override dictionary config for all campaigns
- `--enable-pcap`     Enable PCAP output (default filename)
- `--disable-pcap`    Disable PCAP output
- `--pcap-file <file>`  Specify PCAP output file path
- `--enable-network`   Enable network transmission
- `--disable-network`   Disable network transmission
- `--check-components`  Check if required components (libFuzzer, dictionaries) exist
- `--require-libfuzzer`  Require libFuzzer extension to be available
- `--help`        Show help message and exit

**Examples:**
```bash
# List campaigns
scapy-fuzzer examples/campaign_examples.py --list-campaigns

# Execute campaigns
scapy-fuzzer examples/campaign_examples.py

# Validate campaigns (no packets sent)
scapy-fuzzer examples/campaign_examples.py --dry-run

# Use a custom dictionary config
scapy-fuzzer examples/campaign_examples.py --dictionary-config examples/user_dictionary_config.py

# Enable PCAP output to a specific file
scapy-fuzzer examples/campaign_examples.py --pcap-file output.pcap

# Disable network output
scapy-fuzzer examples/campaign_examples.py --disable-network

# Check component availability
scapy-fuzzer

### Programmatic Usage
```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP

class MyCampaign(FuzzingCampaign):
    name = "My Test Campaign"
    target = "192.168.1.1"
    packet = IP(dst="192.168.1.1") / TCP(dport=FuzzField(values=[80, 443, 8080]))
    iterations = 100

campaign = MyCampaign()
campaign.execute()
```

---

## PCAP-Based Fuzzing

PCAP-based fuzzing supports layer extraction, payload repackaging, and multiple fuzzing modes for regression testing and real-world traffic analysis.

### PCAP Fuzzing Modes

| Mode | Description | Use Case | Example |
|------|-------------|----------|---------|
| `"none"` | Replay packets without fuzzing | Regression testing | Validate against known-good traffic |
| `"field"` | Dictionary-based field fuzzing | Protocol fuzzing | HTTP header/payload fuzzing |
| `"binary"` | Binary mutation with libFuzzer | Low-level protocol testing | Custom protocol analysis |
| `"both"` | Combined field + binary fuzzing | Comprehensive testing | Maximum coverage scenarios |

### Layer Extraction & Repackaging

```
Original PCAP Packet Flow:
┌──────────┬──────────┬──────────┬──────────────┐
│ Ethernet │    IP    │   TCP    │ HTTP Payload │
└──────────┴──────────┴──────────┴──────────────┘

Extract "TCP" → Repackage "IP/TCP":
┌─────────────┬─────────────┬──────────────┐
│  New IP     │  New TCP    │ HTTP Payload │
│ (to target) │ (to target) │   (fuzzed)   │
└─────────────┴─────────────┴──────────────┘
```

```python
from pcapfuzz import PcapFuzzCampaign

# Regression testing - replay without fuzzing
class RegressionTest(PcapFuzzCampaign):
    pcap_folder = "regression_samples/"
    fuzz_mode = "none"
    target = "192.168.1.100"

#TODO add support for providing a packet structure to package it in
# Extract and fuzz HTTP payloads  
class HttpPayloadFuzz(PcapFuzzCampaign):
    pcap_folder = "regression_samples/"
    extract_layer = "TCP"  # Extract TCP payload
    repackage_in = "IP/TCP"  # New headers
    fuzz_mode = "field"  # Dictionary-based fuzzing
    target = "192.168.1.100"
```

## Campaign-Based Fuzzing

Create campaigns using class inheritance with embedded packet configuration:

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class WebAppFuzzCampaign(FuzzingCampaign):
    name = "Web Application Fuzzing"
    target = "192.168.1.100"
    rate_limit = 20.0
    iterations = 100
    output_pcap = "webapp_fuzz.pcap"
    
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(values=[80, 443, 8080, 8443], description="Web ports")) /
        Raw(load=FuzzField(values=[b"GET / HTTP/1.1\r\n\r\n", 
                                  b"GET /admin HTTP/1.1\r\n\r\n"]))
    )
```

## Dictionary Configuration

The framework uses a 3-tier hierarchy for dictionary resolution with comprehensive override capabilities.

### Dictionary Resolution Hierarchy

```
Priority: HIGH ←────────────────────────────────────→ LOW
┌─────────────────┬─────────────────┬──────────────────┐
│  FuzzField      │  Campaign       │    Default       │
│  Dictionaries   │  Overrides      │   Mappings       │
├─────────────────┼─────────────────┼──────────────────┤
│ Inline in       │ User config     │ Built-in field   │
│ packet def      │ files           │ mappings         │
│                 │                 │                  │
│ Highest         │ Medium          │ Lowest           │
│ Priority        │ Priority        │ Priority         │
└─────────────────┴─────────────────┴──────────────────┘
```

### Configuration Methods

| Method | Scope | Priority | Example |
|--------|-------|----------|---------|
| **Inline FuzzField** | Single field | Highest | `FuzzField(dictionaries=["custom.txt"])` |
| **Campaign Class** | Campaign-specific | Medium | `dictionary_config_file = "config.py"` |
| **CLI Override** | Global override | Medium | `--dictionary-config config.py` |
| **Default Mappings** | Framework-wide | Lowest | Built-in field associations |

### Examples

```bash
# CLI dictionary override (affects all campaigns)
scapy-fuzzer examples/campaign_examples.py --dictionary-config examples/user_dictionary_config.py
```

```python
# Campaign class configuration (campaign-specific)
class WebAppCampaign(FuzzingCampaign):
    name = "Custom Dictionary Campaign"
    target = "192.168.1.100"
    dictionary_config_file = "examples/user_dictionary_config.py"  # Campaign-specific
    
    packet = IP(dst="192.168.1.100") / TCP(dport=FuzzField(
        values=[80, 443],
        dictionaries=["custom/web-ports.txt"]  # Highest priority - field-specific
    ))
```

### Dictionary Override Controls

```python
# In user_dictionary_config.py
USER_DICTIONARY_CONFIG = {
    "field_mappings": {
        "TCP.dport": ["custom/ports.txt"],
        "Raw.load": ["custom/payloads.txt"]
    },
    "dictionary_override": {
        "TCP.dport": True,  # Prevents merging with default mappings
        "Raw.load": False   # Merges with default mappings
    }
}
```

## Callback System

The framework provides 6 callback types for comprehensive monitoring and custom logic integration.

### Callback Types & Execution Flow

```
Campaign Execution Flow with Callbacks:
┌─────────────────────────────────────────────────────────────────┐
│                      CAMPAIGN EXECUTION                         │
│                                                                 │
│  1. pre_launch_callback()     ← Validate targets, setup        │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  For each packet iteration:                                 │
│  │                                                             │
│  │  2. pre_send_callback()    ← Modify packet, log            │
│  │           │                                                 │
│  │           ▼                                                 │
│  │  [ SEND PACKET ]           ← Send packet or execute         │
│  │           │                      custom send callback       │
│  │           ▼                                                 │
│  │  3. post_send_callback()   ← Analyze response              │
│  │           │                                                 │
│  │           ▼                                                 │
│  │  4. crash_callback()       ← Handle crashes/errors         │
│  │     (if crash detected)                                     │
│  │                                                             │
│  │  5. monitor_callback()     ← Continuous monitoring         │
│  │     (every N iterations)                                    │
│  └─────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Callback Implementation Examples

```python
from fuzzing_framework import FuzzingCampaign, CallbackResult

class CallbackDemoCampaign(FuzzingCampaign):
    name = "Callback Demo"
    target = "192.168.1.100"
    
    def my_pre_launch_callback(self, context):
        """Validate target before starting campaign"""
        print(f"Validating target: {self.target}")
        # Return CONTINUE, SKIP, or ABORT
        return CallbackResult.CONTINUE
    
    def my_pre_send_callback(self, packet, context):
        """Modify packet before sending"""
        print(f"Sending: {packet.summary()}")
        return CallbackResult.CONTINUE, packet  # Modified packet
    
    def my_post_send_callback(self, packet, response, context):
        """Analyze response after sending"""
        if response:
            print(f"Response: {response.summary()}")
        return CallbackResult.CONTINUE
    
    def my_crash_callback(self, packet, error, context):
        """Handle crashes and errors"""
        print(f"Crash detected: {error}")
        # Log to file, save packet, etc.
        return CallbackResult.CONTINUE
    
    def my_monitor_callback(self, context):
        """Continuous monitoring during campaign"""
        print(f"Progress: {context.get('packets_sent', 0)} packets sent")
        return CallbackResult.CONTINUE
```

### Callback Return Values

| Return Value | Description | Effect |
|--------------|-------------|--------|
| `SUCCESS` | Normal execution | Continue to next step |
| `NO_SUCCESS` | This indicates that the callback did not execute correctly, but that it does not indicate a crash or target failure
| `FAIL_CRASH` | This indicates a target failure, when this is returned the crash callback handler will be executed

## Quick Reference

### Essential Commands

```bash
# Installation
pip install -r requirements.txt

# Run tests  
python tests/run_all_tests.py

# List campaigns
scapy-fuzzer examples/campaign_examples.py --list-campaigns

# Execute with validation
scapy-fuzzer examples/campaign_examples.py --dry-run --verbose

# Execute campaigns
scapy-fuzzer examples/campaign_examples.py --verbose
```

### Key Files

| File | Purpose |
|------|---------|
| `examples/campaign_examples.py` | Standard campaign configurations |
| `examples/basic/01_quick_start.py` | Beginner examples |
| `FRAMEWORK_DOCUMENTATION.md` | Complete API documentation |
| `default_mappings.py` | Field-to-dictionary mappings |
| `tests/run_all_tests.py` | Test suite runner |

### Core Classes

| Class | Purpose | Example Usage |
|-------|---------|---------------|
| `FuzzingCampaign` | Base campaign class | `class MyCampaign(FuzzingCampaign):` |
| `PcapFuzzCampaign` | PCAP-based fuzzing | `class Regression(PcapFuzzCampaign):` |
| `FuzzField` | Field configuration | `TCP(dport=FuzzField(values=[80, 443]))` |
| `CallbackResult` | Callback return values | `return CallbackResult.CONTINUE` |

## Documentation

- `FRAMEWORK_DOCUMENTATION.md` - Complete API documentation  
- `examples/` - Working code examples
- `tests/` - Test suite

## Weight & Priority Resolution

The framework uses sophisticated weight resolution for field prioritization and dictionary selection.

### Weight Resolution Priority Table

| Priority | Source | Example | Weight Range |
|----------|--------|---------|--------------|
| **1 (Highest)** | User-provided in config | `field_weights: {"TCP.dport": 0.95}` | 0.0 - 1.0 |
| **2** | Advanced field mappings | Property-based rules | 0.7 - 0.9 |
| **3** | Name-based patterns | Field name matching | 0.6 - 0.8 |
| **4** | Type-based defaults | Scapy field type | 0.5 - 0.7 |
| **5 (Lowest)** | Framework default | All unmatched fields | 0.5 |

### Advanced Weight Examples

```python
# In user_dictionary_config.py
USER_DICTIONARY_CONFIG = {
    "field_weights": {
        # Explicit field weights (highest priority)
        "TCP.dport": 0.95,        # Very high - critical attack surface
        "Raw.load": 0.90,         # High - payload content
        "IP.dst": 0.30,           # Low - usually fixed target
    },
    
    "property_weights": {
        # Pattern-based weights (medium priority)
        ".*port.*": 0.85,         # Any field with 'port' in name
        ".*addr.*": 0.40,         # Any field with 'addr' in name
        ".*id$": 0.60,            # Fields ending in 'id'
    }
}
```

### Dictionary Resolution Logic

```
For field "TCP.dport":

1. Check FuzzField dictionaries → ["custom/ports.txt"] ✓
2. Check campaign overrides → ["campaign/web-ports.txt"] ✓  
3. Check user config → ["user/common-ports.txt"] ✓
4. Check default mappings → ["fuzzdb/wordlists-misc/common-ports.txt"] ✓

Result: All dictionaries merged (unless override=True specified)
Final: ["custom/ports.txt", "campaign/web-ports.txt", 
        "user/common-ports.txt", "fuzzdb/wordlists-misc/common-ports.txt"]
```



## Troubleshooting

### Common Issues & Solutions

| Issue | Symptom | Solution |
|-------|---------|----------|
| **No mutations** | All packets identical | Check field weights, verify dictionaries exist |
| **Import errors** | ModuleNotFoundError | Run `pip install -r requirements.txt` |
| **Permission denied** | Socket errors | Run with sudo or check network permissions |
| **libFuzzer not working** | Fallback to Python mutator | Install build tools, check `build/` directory |
| **Dictionary not found** | File not found errors | Verify FuzzDB installation, check paths |
| **Callback errors** | Callback exceptions | Check return values (CONTINUE/SKIP/ABORT) |

### Debug Mode

```bash
# Enable verbose logging
scapy-fuzzer examples/campaign_examples.py --verbose

# Dry run for validation
scapy-fuzzer examples/campaign_examples.py --dry-run --verbose

# Test with minimal iterations
python -c "
from examples.campaign_examples import WebAppFuzzCampaign
campaign = WebAppFuzzCampaign()
campaign.iterations = 1
campaign.verbose = True
campaign.dry_run()
"
```
