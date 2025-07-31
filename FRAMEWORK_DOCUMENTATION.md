# PacketFuzz Framework Documentation

## Overview

A network protocol fuzzing framework built on Scapy with embedded packet configuration capabilities and campaign management.

### Key Features
- **Campaign-Based Architecture**: Class inheritance for campaign configuration  
- **Field-Level Control**: Embed fuzzing parameters directly in packet constructors
- **Dictionary Management**: Hierarchical dictionary support with overrides
- **Multiple Fuzzing Modes**: Dictionary-based, binary mutation, and combined approaches
- **PCAP Support**: Load existing captures for regression testing and analysis
- **Callback System**: Hooks for progress monitoring and response analysis
- **Protocol-Agnostic**: Works with any Scapy packet type
- **Response Capture**: Track sent packets, responses, and timing information

## Quick Start

```bash
pip install -r requirements.txt
python tests/run_all_tests.py
python examples/basic/01_quick_start.py
```

## Campaign Configuration

### Basic Campaign Structure

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP

class MyCampaign(FuzzingCampaign):
    name = "My Test Campaign"
    target = "192.168.1.1"
    iterations = 100
    output_pcap = "test.pcap"
    
    packet = (
        IP(dst="192.168.1.1") / 
        TCP(dport=FuzzField(values=[80, 443, 8080], description="Web ports"))
    )

campaign = MyCampaign()
campaign.execute()
```

### FuzzField Configuration Options

| Parameter | Type | Default | Description | Example |
|-----------|------|---------|-------------|---------|
| `values` | `List[Any]` | `[]` | Static values to cycle through | `[80, 443, 8080]` |
| `dictionaries` | `List[str]` | `[]` | Dictionary file paths | `["fuzzdb/wordlists-misc/common-ports.txt"]` |
| `mutators` | `List[str]` | `["libfuzzer"]` | Mutation methods to use | `["libfuzzer", "scapy"]` |
| `description` | `str` | `""` | Human-readable field description | `"Web server ports"` |

### Mutator Types

| Mutator | Description | Use Case | Performance |
|---------|-------------|----------|-------------|
| `"libfuzzer"` | C-based binary mutations | High-performance fuzzing | Very Fast |
| `"scapy"` | Scapy's built-in fuzz() | Protocol-aware mutations | Fast |
| `"dictionary"` | Dictionary-based mutations | Known attack patterns | Medium |
| `"python"` | Pure Python mutations | Fallback when libFuzzer unavailable | Slow |

```python
# Basic FuzzField with values
FuzzField(values=[80, 443, 8080], description="Web ports")

# With dictionary files
FuzzField(values=[80, 443], 
          dictionaries=["fuzzdb/wordlists-misc/common-ports.txt"],
          description="Network ports")

# With custom mutators
FuzzField(values=[80], mutators=["libfuzzer"], description="Port")

# Combined approach - maximum coverage
FuzzField(values=[80, 443, 8080], 
          dictionaries=["fuzzdb/wordlists-misc/common-ports.txt"],
          mutators=["libfuzzer", "dictionary"],
          description="Comprehensive port fuzzing")
```

### Campaign Types

#### Basic Campaign
```python
class BasicCampaign(FuzzingCampaign):
    name = "Basic Test"
    target = "192.168.1.1"
    iterations = 100
    packet = IP(dst="192.168.1.1") / TCP(dport=80)
```

#### PCAP-Based Campaign
```python
from fuzzing_framework import PcapFuzzCampaign

class RegressionCampaign(PcapFuzzCampaign):
    name = "PCAP Regression"
    target = "192.168.1.1"
    pcap_file = "regression_samples/example.pcap"
    layer = 3  # IP layer packets
    fuzz_fields = {
        "TCP": {
            "dport": {"values": [80, 443, 8080]}
        }
    }
```

## Response Tracking System

### FuzzHistoryEntry

The framework automatically tracks sent packets, responses, and timing information using `FuzzHistoryEntry` objects:

```python
@dataclass
class FuzzHistoryEntry:
    """Tracks a single fuzzing iteration with sent packet, response, and crash info"""
    packet: Optional[Packet] = None
    timestamp_sent: Optional[datetime] = None
    timestamp_received: Optional[datetime] = None
    response: Optional[Any] = None
    crashed: bool = False
    crash_info: Optional[CrashInfo] = None
    iteration: int = -1
    
    def get_response_time(self) -> Optional[float]:
        """Calculate response time in milliseconds if both timestamps are available"""
        if self.timestamp_sent and self.timestamp_received:
            delta = self.timestamp_received - self.timestamp_sent
            return delta.total_seconds() * 1000
        return None
```

History entries are stored in the campaign context and accessible in callbacks:

```python
def post_send_callback(self, packet, response, context):
    """Access history after packet is sent"""
    if context.fuzz_history:
        # Get the most recent history entry
        entry = context.fuzz_history[-1]
        
        # Access timing information
        response_time = entry.get_response_time()
        if response_time:
            print(f"Response time: {response_time:.2f} ms")
        
        # Process response packet
        if entry.response:
            print(f"Got response: {entry.response.summary()}")
```

### History Size Management

By default, the campaign context stores up to 1000 history entries to prevent memory issues. You can configure this limit:

```python
class MyFuzzingCampaign(FuzzingCampaign):
    # ... other configuration ...
    
    def pre_launch_callback(self, context):
        # Configure history size based on your needs
        context.max_history_size = 500
        return True
```

### Crash Correlation

When a crash occurs, the framework automatically associates it with the history entry that caused it:

```python
def crash_callback(self, crash_info, context):
    """Handle crashes with full history context"""
    if context.fuzz_history:
        for entry in context.fuzz_history:
            if entry.crashed and entry.crash_info == crash_info:
                print(f"Found crash in history for packet {entry.packet.summary()}")
                print(f"Response time before crash: {entry.get_response_time()} ms")
```
    pcap_file = "samples/traffic.pcap"
    target = "192.168.1.100"
    iterations = 200
```

## Campaign Execution

### Configuration Attributes

| Category | Attribute | Type | Default | Description |
|----------|-----------|------|---------|-------------|
| **Required** | `name` | `str` | `"Unnamed Campaign"` | Campaign identifier |
| | `target` | `str` | `"127.0.0.1"` | Target IP address |
| **Execution** | `iterations` | `int` | `100` | Number of packets to send |
| | `duration` | `Optional[int]` | `None` | Max execution time (seconds) |
| | `rate_limit` | `int` | `1` | Packets per second |
| **Output** | `output_pcap` | `Optional[str]` | `None` | Output PCAP filename |
| | `verbose` | `bool` | `False` | Enable detailed logging |
| | `interface` | `Optional[str]` | `None` | Network interface (Layer 2) |
| **Safety** | `output_network` | `bool` | `False` | Actually send packets |
| | `dry_run_mode` | `bool` | `False` | Validation only mode |

### Execution Flow Diagram

```
Campaign Execution Lifecycle:
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    CAMPAIGN EXECUTION                                                       │  
│                                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────┐    │
│  │   SETUP      │ →  │   VALIDATE   │ →  │   INITIALIZE   │    │
│  │              │    │              │    │                │    │
│  │ • Load config│    │ • Check target│    │ • Setup PCAP   │    │  
│  │   Parse packet│    │ • Validate packet│ │ • Init mutator│    │
│  │              │    │              │    │ • Load dicts   │    │
│  └──────────────┘    └──────────────┘    └────────────────┘    │
│                                                                                              │
│         ┌──────────────────────────────────────────────────────────────┐                     │
│         │           ITERATION LOOP                                    │                     │
│         │                                                            │                     │
│         │  ┌──────────┐ → ┌──────────┐ → ┌──────────┐ │               │
│         │  │  MUTATE  │   │   SEND   │   │  STORE   │ │               │
│         │  │          │   │          │   │          │ │               │
│         │  │ • Apply  │   │ • Rate   │   │ • Log    │ │               │
│         │  │   fuzz   │   │   limit  │   │ • Save   │ │               │
│         │  │ • Dict   │   │ • Trans- │   │  PCAP    │ │               │
│         │  │   values │   │   mit    │   │          │ │               │
│         │  └──────────┘   └──────────┘   └──────────┘ │               │
│         └──────────────────────────────────────────────────────────────┘                     │
│                                                                                              │
│  ┌──────────────┐    ┌────────────────────┐                                                  │
│  │   CLEANUP    │ ←  │     FINALIZE       │                                                  │
│  │              │    │                    │                                                  │
│  │ • Close files│    │ • Write final PCAP │                                                  │
│  │ • Save logs  │    │ • Generate reports │                                                  │
│  │ • Cleanup temp│   │ • Call completion  │                                                  │
│  │              │    │   callbacks        │                                                  │
│  └──────────────┘    └────────────────────┘                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Execution Methods

```python
campaign = MyCampaign()

# Standard execution
campaign.execute()

# Dry run (validation only)
campaign.dry_run()

# With callback hooks
def progress_callback(sent: int, total: int):
    print(f"Progress: {sent}/{total}")

def response_callback(response):
    print(f"Response: {response.summary()}")

campaign.on_progress = progress_callback
campaign.on_response = response_callback
campaign.execute()
```

## Dictionary Management

### Hierarchy & Resolution

The framework uses a 3-tier hierarchical system for dictionary resolution with sophisticated merging and override capabilities.

```
Dictionary Resolution Flow:
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    DICTIONARY RESOLUTION                                                    │
│                                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │  FUZZFIELD   │ →  │   CAMPAIGN   │ →  │  DEFAULT  │ │
│  │ DICTIONARIES │    │  OVERRIDES   │    │ MAPPINGS  │ │
│  │              │    │              │    │           │ │
│  │ Inline in    │    │ User config  │    │ Built-in  │ │
│  │ packet def   │    │ files        │    │ field maps│ │
│  │              │    │              │    │           │ │
│  │ Priority: 1  │    │ Priority: 2  │    │ Priority:3│ │
│  │ (Highest)    │    │ (Medium)     │    │ (Lowest)  │ │
│  └──────────────┘    └──────────────┘    └───────────┘ │
│                                                                                              │
│                            ↓                                                                 │
│                   ┌──────────────┐                                                          │
│                   │  MERGE LOGIC │                                                          │
│                   │              │                                                          │
│                   │ • Check override flags                                                  │
│                   │ • Combine lists                                                         │
│                   │ • Remove dupes                                                          │
│                   │ • Validate paths                                                        │
│                   └──────────────┘                                                          │
│                            ↓                                                                 │
│                   ┌──────────────┐                                                          │
│                   │ FINAL DICTIONARY LIST                                                   │
│                   │      LIST     │                                                          │
│                   └──────────────┘                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Dictionary Sources & Priority

| Priority | Source | Scope | Override Control | Example |
|----------|--------|-------|------------------|---------|
| **1** | FuzzField | Single field | Not applicable | `FuzzField(dictionaries=["custom.txt"])` |
| **2** | Campaign Config | Campaign-wide | `dictionary_override` flag | `dictionary_config_file = "config.py"` |
| **3** | CLI Override | Global | Command-line flag | `--dictionary-config config.py` |
| **4** | Default Mappings | Framework | Built-in rules | Automatic field associations |

### Configuration Examples

```python
# default_mappings.py - Framework defaults
default_field_mappings = {
    "TCP.dport": ["fuzzdb/wordlists-misc/common-ports.txt"],
    "Raw.load": ["fuzzdb/attack-payloads/all-attacks/all-attacks-unix.txt"],
    "DNS.qname": ["fuzzdb/discovery/dns/dns-names.txt"]
}

# user_dictionary_config.py - User overrides
USER_DICTIONARY_CONFIG = {
    "field_mappings": {
        "TCP.dport": ["custom/ports.txt"],          # Replaces default
        "Raw.load": ["custom/payloads.txt"]         # Replaces default  
    },
    "dictionary_override": {
        "TCP.dport": True,   # Don't merge with lower priority
        "Raw.load": False    # Merge with lower priority
    }
}

# Campaign override example
class MyCampaign(FuzzingCampaign):
    dictionary_overrides = {
        "TCP.dport": ["campaign/specific-ports.txt"]
    }
    
    packet = (
        IP() / 
        TCP(dport=FuzzField(
            values=[80, 443],
            dictionaries=["inline/priority-ports.txt"]  # Highest priority
        ))
    )
```

### Dictionary Merging Logic

```
Example Resolution for "TCP.dport":

1. FuzzField dictionaries:     ["inline/priority-ports.txt"]        
2. Campaign overrides:         ["campaign/specific-ports.txt"]      
3. User config (override=False): ["custom/ports.txt"]               
4. Default mappings:           ["fuzzdb/wordlists-misc/common-ports.txt"] 

Final Result: 
[
  "inline/priority-ports.txt",           # Priority 1
  "campaign/specific-ports.txt",         # Priority 2  
  "custom/ports.txt",                    # Priority 3
  "fuzzdb/wordlists-misc/common-ports.txt" # Priority 4
]

If override=True for user config:
[
  "inline/priority-ports.txt",           # Priority 1
  "campaign/specific-ports.txt",         # Priority 2
  "custom/ports.txt"                     # Priority 3 (stops here)
]
```

## CLI Interface

```bash
# List campaigns
packetfuzz examples/campaign_examples.py --list-campaigns

# Run campaign
packetfuzz examples/campaign_examples.py --campaign WebAppFuzzCampaign

# Dry run
packetfuzz examples/campaign_examples.py --campaign DNSInfrastructureFuzzCampaign --dry-run

# Verbose mode
packetfuzz examples/campaign_examples.py --campaign NetworkConnectivityFuzzCampaign --verbose
```

## Advanced Features

### Callback System Architecture

The framework provides 5 callback types for comprehensive campaign control and monitoring.

#### Callback Types & Context

| Callback Type | Timing | Context Provided | Return Value | Use Cases |
|---------------|--------|------------------|--------------|-----------|
| `pre_launch_callback` | Before campaign starts | Campaign config | `CallbackResult` | Target validation, setup |
| `pre_send_callback` | Before each packet | Packet, iteration info | `CallbackResult` | Packet modification, logging |
| `custom_send_callback` | Sends each packet | Packet, response, timing | `CallbackResult` | Implements custom send functions |
| `post_send_callback` | After each packet | Packet, response, timing | `CallbackResult` | Response analysis, metrics |
| `crash_callback` | On errors/crashes | Packet, error, context | `CallbackResult` | Error handling, crash logging |
| `no_success_callback` | On no_success | Packet, error, context | `CallbackResult` | Error handling, crash logging |
| `monitor_callback` | Periodic intervals | Progress, statistics | `CallbackResult` | Progress monitoring, alerts |

#### Callback Implementation Pattern

```python
from fuzzing_framework import CallbackResult

class AdvancedCampaign(FuzzingCampaign):
    
    def my_pre_launch_callback(self, context):
        """Validate target accessibility before starting"""
        try:
            # Ping target, check ports, validate config
            response = ping(self.target)
            if not response:
                print(f"Target {self.target} not reachable")
                return CallbackResult.ABORT
        except Exception as e:
            print(f"Pre-launch validation failed: {e}")
            return CallbackResult.ABORT
        return CallbackResult.CONTINUE
    
    def my_pre_send_callback(self, packet, context):
        """Modify packet based on previous responses"""
        iteration = context.get('iteration', 0)
        
        # Dynamic packet modification based on iteration
        if iteration > 100:
            # Increase aggressiveness after initial probing
            if hasattr(packet, 'payload') and packet.payload:
                packet.payload = b"AGGRESSIVE_PAYLOAD_" + packet.payload
        
        return CallbackResult.CONTINUE, packet
    
    def my_post_send_callback(self, packet, response, context):
        """Analyze responses for interesting behaviors"""
        if response:
            response_time = context.get('response_time', 0)
            
            # Detect slow responses (potential DoS)
            if response_time > 5.0:
                print(f"Slow response detected: {response_time}s")
                self._log_slow_response(packet, response, response_time)
            
            # Detect large responses (potential information disclosure)
            if len(response) > 10000:
                print(f"Large response: {len(response)} bytes")
                self._log_large_response(packet, response)
                
        return CallbackResult.CONTINUE
    
    def my_crash_callback(self, packet, error, context):
        """Comprehensive crash handling and logging"""
        timestamp = datetime.now().isoformat()
        
        # Save crash artifacts
        crash_data = {
            'timestamp': timestamp,
            'packet_summary': packet.summary(),
            'packet_hex': packet.build().hex(),
            'error': str(error),
            'context': context
        }
        
        # Write to crash log
        with open(f"crash_logs/crash_{timestamp}.json", "w") as f:
            json.dump(crash_data, f, indent=2)
        
        # Save packet to PCAP
        wrpcap(f"crash_logs/crash_{timestamp}.pcap", packet)
        
        return CallbackResult.CONTINUE  # Continue despite crash
    
    def my_monitor_callback(self, context):
        """Continuous monitoring and statistics"""
        sent = context.get('packets_sent', 0)
        total = context.get('total_iterations', 0)
        
        # Progress reporting
        if sent % 100 == 0:
            print(f"Progress: {sent}/{total} ({sent/total*100:.1f}%)")
        
        # Resource monitoring
        memory_usage = self._get_memory_usage()
        if memory_usage > 5000 * 1024 * 1024:  # 5000MB
            print(f"High memory usage: {memory_usage/1024/1024:.1f}MB")
            return CallbackResult.ABORT  # Stop if memory too high
            
        return CallbackResult.CONTINUE
```

### Field Resolution & Discovery

The framework uses dynamic field discovery to work with any Scapy packet type, including custom protocols.

#### Field Discovery Process

```
Packet Field Discovery Flow:
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    FIELD DISCOVERY PROCESS                                                  │
│                                                                                              │
│  Input: Scapy Packet                                                                         │
│         │                                                                                   │
│         ▼                                                                                   │
│  ┌──────────────┐                                                                           │
│  │ LAYER ANALYSIS│                                                                           │
│  │              │                                                                           │
│  │ • Extract all│ ────────────────────────────────────────────────────────────────────────┐ │
│  │   packet layers│                       │                                               │
│  │ • Get layer   │                       │                                               │
│  │   class names │                       │                                               │
│  └──────────────┘                       │                                               │
│                                         │                                               │
│         ┌───────────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                               │
│         ▼                                                                               │
│  ┌──────────────┐    ┌──────────────┐                                                   │
│  │FIELD DETECTION│    │FALLBACK      │                                                   │
│  │              │    │DETECTION     │                                                   │
│  │ • Use Scapy's│    │              │                                                   │
│  │   fields_desc│ ──▶│ • Scan __dict__│                                                   │
│  │ • Extract field│   │ • Filter private│                                                   │
│  │   names & types│   │   attributes  │                                                   │
│  └──────────────┘    └──────────────┘                                                   │
│                                         │                                               │
│         ┌───────────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                               │
│         ▼                                                                               │
│  ┌──────────────┐                                                                       │
│  │FIELD MAPPING │                                                                       │
│  │              │                                                                       │
│  │ • Create layer.│                                                                       │
│  │   field paths │                                                                       │
│  │ • Map to      │                                                                       │
│  │   dictionaries│                                                                       │
│  │ • Apply weights│                                                                       │
│  └──────────────┘                                                                       │
│                                                                                        │
│  Output: List of fuzzable fields with metadata                                          │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Custom Protocol Example

This examples shows how a custom protocol can easily be added by using basic scapy packet crafting.

```python
from scapy.packet import Packet
from scapy.fields import ByteField, ShortField, StrField, IPField

# Define custom protocol
class MyCustomProtocol(Packet):
    name = "MyCustomProtocol"
    fields_desc = [
        ByteField("version", 1),
        ShortField("command", 0), 
        IPField("target_ip", "0.0.0.0"),
        StrField("payload", "")
    ]

# Framework automatically discovers these fields:
# MyCustomProtocol.version  → Type: ByteField
# MyCustomProtocol.command  → Type: ShortField  
# MyCustomProtocol.target_ip → Type: IPField
# MyCustomProtocol.payload  → Type: StrField

class CustomProtocolCampaign(FuzzingCampaign):
    name = "Custom Protocol Test"
    target = "192.168.1.1"
    
    packet = (
        IP(dst="192.168.1.1") / 
        UDP(dport=9999) /
        MyCustomProtocol(
            version=FuzzField(values=[1, 2, 255], description="Protocol version"),
            command=FuzzField(
                dictionaries=["custom/protocol-commands.txt"],
                description="Protocol commands"
            ),
            payload=FuzzField(
                dictionaries=["fuzzdb/attack-payloads/all-attacks/all-attacks-unix.txt"],
                description="Protocol payload"
            )
        )
    )
```

### Performance Optimization

#### LibFuzzer Integration

The framework integrates with libFuzzer's high-performance mutation engine through a C extension.

```
LibFuzzer Integration Architecture:
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                    LIBFUZZER INTEGRATION                                                    │
│                                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │PYTHON LAYER  │ ─▶ │ C EXTENSION  │ ─▶ │LIBFUZZER │ │
│  │              │    │              │    │          │ │
│  │ • Field data │    │ • Data       │    │ • Coverage│ │
│  │ • Dictionary │    │   conversion │    │   guided │ │
│  │ • Configuration│  │ • libFuzzer  │    │   mutations│ │
│  │              │    │   interface  │    │          │ │
│  └──────────────┘    └──────────────┘    └──────────┘ │
│                                                                                              │
│  Fallback Path (if libFuzzer unavailable):                                                   │
│  ┌──────────────┐    ┌──────────────┐                                                       │
│  │PYTHON LAYER  │ ─▶ │PYTHON MUTATOR│                                                       │
│  │              │    │              │                                                       │
│  │ • Same interface│ │ • Pure Python│                                                       │
│  │ • Same API   │    │ • Compatible │                                                       │
│  └──────────────┘    └──────────────┘                                                       │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Performance Comparison

| Mutator | Speed | Coverage | Memory | Use Case |
|---------|-------|----------|--------|----------|
| LibFuzzer | Very Fast | Excellent | Low | Production fuzzing |
| Scapy Native | Fast | Good | Medium | Protocol-aware testing |
| Dictionary | Medium | Targeted | Low | Known attack patterns |
| Python | Slow | Good | Medium | Development/Fallback |

### Corpus Management

LibFuzzer uses corpus directories for seed management and coverage tracking.

```python
# The framework automatically manages corpus directories per field
# No user intervention required - handled internally

# Internal process (for reference):
with tempfile.TemporaryDirectory(prefix=f"corpus_{field_name}_") as corpus_dir:
    # Write dictionary entries as seed files
    for i, entry in enumerate(dictionary_entries):
        with open(f"{corpus_dir}/seed_{i}", "wb") as f:
            f.write(entry)
    
    # Set environment for C extension
    os.environ["SCAPY_LIBFUZZER_CORPUS"] = corpus_dir
    
    # Perform mutation
    result = libfuzzer_mutate(data, max_size)
    
    # Cleanup automatic - temp directory deleted
```

## Testing

```bash
python tests/run_all_tests.py
```

## API Reference

### FuzzingCampaign Attributes
- `name: str` - Campaign name
- `target: str` - Target IP address  
- `iterations: int` - Number of packets to send
- `rate_limit: int` - Packets per second
- `output_pcap: Optional[str]` - Output PCAP file
- `packet: Packet` - Packet template to fuzz

### FuzzField Parameters
- `values: List[Any]` - Static values to use
- `dictionaries: List[str]` - Dictionary file paths
- `mutators: List[str]` - Mutation methods (`["libfuzzer"]`, `["scapy"]`, etc.)
- `description: str` - Field description

### Methods
- `campaign.execute()` - Run the campaign
- `campaign.dry_run()` - Validate without execution

## Examples

### Comprehensive HTTP Fuzzing

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class HTTPCampaign(FuzzingCampaign):
    name = "HTTP Comprehensive Test"
    target = "192.168.1.100" 
    iterations = 500
    rate_limit = 10  # Safe rate limiting
    output_pcap = "http_comprehensive.pcap"
    verbose = True
    
    # Multi-field fuzzing with different strategies
    packet = (
        IP(dst="192.168.1.100") / 
        TCP(dport=FuzzField(
            values=[80, 443, 8080, 8443],
            dictionaries=["fuzzdb/wordlists-misc/common-http-ports.txt"],
            mutators=["libfuzzer", "dictionary"],
            description="HTTP/HTTPS ports with mutations"
        )) /
        Raw(load=FuzzField(
            values=[
                b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
                b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ntest"
            ],
            dictionaries=[
                "fuzzdb/attack-payloads/http-protocol-attacks/http-injection.txt",
                "fuzzdb/attack-payloads/sql-injection/generic-sqli.txt"
            ],
            mutators=["dictionary", "libfuzzer"],
            description="HTTP requests with injection payloads"
        ))
    )
    
    # Custom callback for response analysis
    def my_post_send_callback(self, packet, response, context):
        if response and hasattr(response, 'show'):
            # Log interesting responses
            if len(response) > 100:  # Large response
                print(f"Large response detected: {len(response)} bytes")
        return CallbackResult.CONTINUE
```

### DNS Infrastructure Testing

```python
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP

class DNSCampaign(FuzzingCampaign):
    name = "DNS Infrastructure Test"
    target = "8.8.8.8"
    iterations = 200
    
    packet = (
        IP(dst="8.8.8.8") / 
        UDP(dport=53) /
        DNS(
            id=FuzzField(
                values=[0x1234, 0x5678],
                mutators=["libfuzzer"],
                description="DNS transaction ID"
            ),
            qd=DNSQR(
                qname=FuzzField(
                    values=["example.com", "test.org"],
                    dictionaries=[
                        "fuzzdb/discovery/dns/dns-names.txt",
                        "fuzzdb/attack/file-path-traversal/file-path-traversal-8.txt"
                    ],
                    description="DNS query names with traversal attempts"
                )
            )
        )
    )
```

### PCAP Regression Testing

```python
from fuzzing_framework import PcapFuzzCampaign

class HTTPRegressionCampaign(PcapFuzzCampaign):
    name = "HTTP PCAP Regression"
    pcap_file = "samples/http_traffic.pcap"
    target = "192.168.1.100"
    
    # Extract HTTP payloads and repackage
    extract_layer = "TCP"        # Extract TCP payload (HTTP data)
    repackage_in = "IP/TCP"      # Wrap in new IP/TCP headers
    fuzz_mode = "field"          # Use field-aware fuzzing
    
    iterations = 100
    output_pcap = "regression_fuzzed.pcap"

class BinaryProtocolRegression(PcapFuzzCampaign):
    name = "Binary Protocol Regression"  
    pcap_file = "samples/custom_protocol.pcap"
    target = "10.0.0.1"
    
    # Binary-level mutations for unknown protocols
    extract_layer = "UDP"        # Extract UDP payload
    repackage_in = "IP/UDP"      # Repackage with new headers
    fuzz_mode = "binary"         # Pure binary mutations
    
    iterations = 300
```

### Multi-Protocol Campaign with Callbacks

```python
class NetworkReconCampaign(FuzzingCampaign):
    name = "Network Reconnaissance"
    target = "192.168.1.0/24"  # Network range
    iterations = 1000
    
    # Combine multiple protocols
    packets = [
        # ICMP ping variations
        IP(dst="192.168.1.1") / ICMP(
            type=FuzzField(values=[8, 13, 15], description="ICMP types")
        ),
        
        # ARP requests  
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            pdst=FuzzField(
                values=["192.168.1.1", "192.168.1.2"],
                description="ARP targets"
            )
        ),
        
        # TCP SYN scan
        IP(dst="192.168.1.1") / TCP(
            dport=FuzzField(
                dictionaries=["fuzzdb/wordlists-misc/common-ports.txt"],
                description="Common service ports"
            ),
            flags="S"
        )
    ]
    
    def my_pre_launch_callback(self, context):
        print("Starting network reconnaissance...")
        # Could validate network access, setup monitoring, etc.
        return CallbackResult.CONTINUE
    
    def my_crash_callback(self, packet, error, context):
        # Log network errors, connection issues, etc.
        with open("network_errors.log", "a") as f:
            f.write(f"{datetime.now()}: {packet.summary()} - {error}\n")
        return CallbackResult.CONTINUE
```
