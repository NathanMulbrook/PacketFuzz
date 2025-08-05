# PacketFuzz - Advanced Network Protocol Fuzzing Framework

The goal of this project is to combine the mutation capabilities of libfuzzer with the predefined protocols and ease of implenting new protocols in scapy. fuzzdb was added to provide a dictionary dataset to be used murring mutation. This project provides a framework that allows the user to very quickly create high quality protocol fuzzers, but also has the flexability to implement custom protocols, and fuzz stategies when needed. The design of this application attempts to replicate some of the user facing configuration ideas present in scapy.

Many of the features and ideas are inspired by boofuzz and similar fuzzers. Once complete this project should have all the features and abilities that boofuzz has with the added advantage of greater flexability and less time to develop a fuzzer by using scapy's extensive protocol definitions.

The structure of this project consistes of 3 main components, a libfuzzer interface for fuzzing individual fields without needing a astandard libfuzz harness, a mutator manager that accepts scapy packets for fuzzing, and a fuzzing framework that allows the suer to define fuzz campaings. For more advanced usage the fuzzer can be used without the campaign framework.
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

## Network Interface Offload Management

When fuzzing with malformed packets, network interface offload features, both those implemented in drivers, firmware and hardware can interfere by automatically "fixing" corrupted checksums, segmentation, and other intentionally malformed packet attributes before transmission. PacketFuzz provides automatic netowork interface configuration to disable these features during fuzzing campaigns. By default it will restore the previous settings when it exits.

### Included disabled offload features
Note that this can be changed or expanded by the user if needed.

| Feature | Purpose | Fuzzing Impact |
|---------|---------|----------------|
| **TX Checksumming** | Hardware calculates checksums | Overwrites intentionally invalid checksums |
| **TCP Segmentation Offload (TSO)** | Hardware handles large packet segmentation | Modifies packet structure during transmission |
| **Generic Segmentation Offload (GSO)** | Generic packet segmentation | Alters packet boundaries and headers |
| **Generic Receive Offload (GRO)** | Packet aggregation on receive | Affects response packet analysis |
| **Large Receive Offload (LRO)** | Large packet reassembly | Changes received packet structure |

### Configuration in a Campaign 

```python
from fuzzing_framework import FuzzingCampaign
from scapy.layers.inet import IP, TCP

class MalformedPacketCampaign(FuzzingCampaign):
    name = "Malformed Packet Test"
    target = "192.168.1.100"
    
    # Enable interface offload management
    disable_interface_offload = True
    interface = "eth0"
    interface_offload_restore = True  # Restore settings when done (default)
    
    # Optional: specify which features to disable (None = use defaults)
    # interface_offload_features = ["tx-checksumming", "tcp-segmentation-offload"]
    
    packet = IP() / TCP(chksum=0x0000)  # Invalid checksum
```

### CLI Usage

```bash
# Enable interface offload management for all campaigns
sudo packetfuzz --disable-offload campaign_config.py

# Disable interface offload management (keep hardware features enabled)
packetfuzz --enable-offload campaign_config.py

# Root privileges required for interface configuration
sudo python packetfuzz.py --disable-offload examples/malformed_packets.py
```

### Default Offload Features

When `disable_interface_offload = True`, the following features are disabled by default:

- `tx-checksumming` - Transmit checksum offloading
- `rx-checksumming` - Receive checksum offloading  
- `tcp-segmentation-offload` - TCP segmentation offload (TSO)
- `generic-segmentation-offload` - Generic segmentation offload (GSO)
- `generic-receive-offload` - Generic receive offload (GRO)
- `large-receive-offload` - Large receive offload (LRO)

### Requirements

- **Root privileges**: Interface configuration requires administrator access
- **ethtool**: System must have `ethtool` command available
- **Valid interface**: Specified network interface must exist

### Error Handling

The framework uses **hard fail** behavior by default:
- If interface configuration fails, the campaign stops with an error
- Use CLI flags to override campaign settings if needed
- Original interface settings are automatically restored after campaign completion

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

Create campaigns using class inheritance with embedded packet configuration. The user adds all campaigns to a `CAMPAIGNS` list, this list is then read when you pass a file with campaigns in it to the CLI.

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest

class WebAppFuzzCampaign(FuzzingCampaign):
    name = "Web Application Fuzzing"
    target = "192.168.1.100"
    rate_limit = 20.0
    iterations = 100
    output_pcap = "webapp_fuzz.pcap"
    
    packet = (
        IP() /
        TCP() /
        HTTP() /
        HTTPRequest(Path=b"/", Method=b"GET")
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
packetfuzz examples/campaign_examples.py --dictionary-config examples/user_dictionary_config.py
```

```python
# Campaign class configuration (campaign-specific)
class WebAppCampaign(FuzzingCampaign):
    name = "Custom Dictionary Campaign"
    target = "192.168.1.100"
    dictionary_config_file = "examples/user_dictionary_config.py"  # Campaign-specific
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(
        Path=b"/",
        Method=b"GET",
        dictionaries=["custom/web-ports.txt"]  # Highest priority - field-specific
    )
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

The framework provides 6 callback types for comprehensive monitoring and custom logic integration. These callbacks can be optionally implemented in a campaign by the user. When provided they are caled at various points throughout the fuzz campaing execution.

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


## Network Interface Offload Management

When fuzzing with malformed packets, network interface offload features, both those implemented in drivers, firmware and hardware can interfere by automatically "fixing" corrupted checksums, segmentation, and other intentionally malformed packet attributes before transmission. PacketFuzz provides automatic netowork interface configuration to disable these features during fuzzing campaigns. By default it will restore the previous settings when it exits.

### Included disabled offload features
Note that this can be changed or expanded by the user if needed.

| Feature | Purpose | Fuzzing Impact |
|---------|---------|----------------|
| **TX Checksumming** | Hardware calculates checksums | Overwrites intentionally invalid checksums |
| **TCP Segmentation Offload (TSO)** | Hardware handles large packet segmentation | Modifies packet structure during transmission |
| **Generic Segmentation Offload (GSO)** | Generic packet segmentation | Alters packet boundaries and headers |
| **Generic Receive Offload (GRO)** | Packet aggregation on receive | Affects response packet analysis |
| **Large Receive Offload (LRO)** | Large packet reassembly | Changes received packet structure |

### Configuration in a Campaign 

```python
from fuzzing_framework import FuzzingCampaign
from scapy.layers.inet import IP, TCP

class MalformedPacketCampaign(FuzzingCampaign):
    name = "Malformed Packet Test"
    target = "192.168.1.100"
    
    # Enable interface offload management
    disable_interface_offload = True
    interface = "eth0"
    interface_offload_restore = True  # Restore settings when done (default)
    
    # Optional: specify which features to disable (None = use defaults)
    # interface_offload_features = ["tx-checksumming", "tcp-segmentation-offload"]
    
    packet = IP() / TCP(chksum=0x0000)  # Invalid checksum
```

## Weight & Priority Resolution

The framework uses sophisticated weight resolution for field prioritization and dictionary selection. The applicaiton comes with a basic set of weights and dictionaries that should work for most or at least be a good starting point, these can be extended or overridden by the user depending on there needs

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

### Dictionary Resolution Logic Example

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
