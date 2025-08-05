# PacketFuzz - Advanced Network Protocol Fuzzing Framework

The goal of this project is to combine the mutation capabilities of libfuzzer with the predefined protocols and ease of implenting new protocols in scapy. fuzzdb was added to provide a dictionary dataset to be used murring mutation. This project provides a framework that allows the user to very quickly create high quality protocol fuzzers, but also has the flexability to implement custom protocols, and fuzz stategies when needed. The design of this application attempts to replicate some of the user facing configuration ideas present in scapy.

Many of the features and ideas are inspired by boofuzz and similar fuzzers. Once complete this project should have all the features and abilities that boofuzz has with the added advantage of greater flexability and less time to develop a fuzzer by using scapy's extensive protocol definitions.

The structure of this project consistes of 3 main components, a libfuzzer interface for fuzzing individual fields without needing a astandard libfuzz harness, a mutator manager that accepts scapy packets for fuzzing, and a fuzzing framework that allows the suer to define fuzz campaings. For more advanced usage the fuzzer can be used without the campaign framework.

For detailed usage information, please see the [framework documentation](FRAMEWORK_DOCUMENTATION.md).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      SCAPY FUZZING FRAMEWORK                    │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface (packetfuzz.py)                               │
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
│  └─ Dictionary-Only (Exact dictionary values)                 │
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
| **Interface Offload Management** | Disable network hardware offloading | Ensures malformed packets reach targets |
| **Multiple Mutation Modes** | LibFuzzer, Scapy, Dictionary-only, Combined | Comprehensive coverage, flexibility |
| **PCAP Integration** | Load/replay captures with fuzzing | Regression testing, real-world scenarios |
| **Callback System** | 5 callback types with full context | Custom logic, monitoring, crash handling |
| **Response Capture** | Track packets, responses and timing | Analysis of network behavior, debugging |
| **Rate Limiting** | Network-safe packet transmission | Responsible testing, DoS prevention |
| **Protocol Agnostic** | Works with any Scapy packet type | Universal applicability |

---

## Project Structure

```
PacketFuzz/
├── examples/                   # Example scripts and campaign configs
│   ├── basic/                  # Basic examples for simple settup
│   ├── advanced/               # Advanced features and patterns
│   ├── intermediate/           # Intermediate features
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
├── packetfuzz.py               # Command-line interface
├── FRAMEWORK_DOCUMENTATION.md  # API and usage documentation
├── requirements.txt            # Python dependencies
└── setup.py                    # Package setup
```

---

## Installation
Instalation is not necessarily required, the application can be executed from the application source, but the libfuzzer componenets must be built.

### Quick Install
```bash
pip install -r requirements.txt
```

### Development Install
```bash
pip install -e .
```

This installs the `packetfuzz` command-line tool.

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
packetfuzz [OPTIONS] <campaign_config.py>
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
packetfuzz examples/campaign_examples.py --list-campaigns

# Execute campaigns
packetfuzz examples/campaign_examples.py

# Use a custom dictionary config
packetfuzz examples/campaign_examples.py --dictionary-config examples/user_dictionary_config.py

# Enable PCAP output to a specific file
packetfuzz examples/campaign_examples.py --pcap-file output.pcap

# Check component availability
packetfuzz

### Programmatic Usage
```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest

class MyCampaign(FuzzingCampaign):
    name = "My Test Campaign"
    target = "192.168.1.1"
    packet = IP() / TCP() / HTTP() / HTTPRequest(Path=b"/", Method=b"GET")
    iterations = 100

campaign = MyCampaign()
campaign.execute()
```

---






## Quick Reference

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




## Troubleshooting

### Debug Mode

```bash
# Enable verbose logging
packetfuzz examples/campaign_examples.py --verbose

# Dry run for validation
packetfuzz examples/campaign_examples.py --dry-run --verbose

# Test with minimal iterations
python -c "
from examples.campaign_examples import WebAppFuzzCampaign
campaign = WebAppFuzzCampaign()
campaign.iterations = 1
campaign.verbose = True
campaign.dry_run()
"
```
