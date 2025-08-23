# PacketFuzz Framework Documentation

## Campaign Configuration
Create campaigns using class inheritance with embedded packet configuration. The user adds all campaigns to a `CAMPAIGNS` list, this list is then read when you pass a file with campaigns in it to the CLI.

### Basic Campaign Structure

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest

class MyCampaign(FuzzingCampaign):
    name = "My Test Campaign"
    target = "192.168.1.1"
    iterations = 100
    output_pcap = "test.pcap"
    
    packet = (
        IP() /
        TCP() /
        HTTP() /
        HTTPRequest(Path=b"/", Method=b"GET")
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

### Fuzzing Modes

| Mode | Description | Use Case | Example |
|------|-------------|----------|---------|
| `"none"` | Replay packets without fuzzing | Regression testing | Validate against known-good traffic |
| `"field"` | Dictionary-based field fuzzing | Protocol fuzzing | HTTP header/payload fuzzing |
| `"binary"` | Binary mutation with libFuzzer | Low-level protocol testing | Custom protocol analysis |
| `"both"` | Combined field + binary fuzzing | Comprehensive testing | Maximum coverage scenarios |

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


## PCAP-Based Fuzzing

PCAP-based fuzzing supports layer extraction, payload repackaging, and multiple fuzzing modes for regression testing and real-world traffic analysis. The fuzzer will read the packet and first attempt to convert the entire packet into scapy objects, if that fails it will fall back to treating the payload as binary data.


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
    extract_layer = "TCP"  # Extract TCP payload  #TODO not implemented yet
    repackage_in = "IP/TCP"  # New headers #TODO replace this with a provided scapy packet to repackage in.
    fuzz_mode = "field" 
    target = "192.168.1.100"
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

    pcap_file = "samples/traffic.pcap"
    target = "192.168.1.100"
    iterations = 200
```

## Campaign Execution

### Configuration Attributes

| Category     | Attribute      | Type            | Default           | Description                                      |
|--------------|---------------|-----------------|-------------------|--------------------------------------------------|
| **Required** | `name`        | `str`           | `"Unnamed Campaign"` | Campaign identifier                          |
|              | `target`      | `str`           | `"127.0.0.1"`     | Target IP address                                |
| **Execution**| `iterations`  | `int`           | `100`             | Number of packets to send                        |
|              | `duration`    | `Optional[int]` | `None`            | Max execution time (seconds)                     |
|              | `rate_limit`  | `int`           | `1`               | Packets per second                               |
| **Output**   | `output_pcap` | `Optional[str]` | `None`            | Output PCAP filename                             |
|              | `verbose`     | `bool`          | `False`           | Enable detailed logging                          |
|              | `interface`   | `Optional[str]` | `None`            | Network interface (Layer 2)                      |
| **Network**  | `socket_type` | `Optional[str]` | `None`            | Socket type: `"canbus"`, `"l2"`, `"l3"`, `"udp"`, `"tcp"`; auto-detect if `None` |
| **Safety**   | `output_network` | `bool`        | `False`           | Actually send packets                            |
| **Scaling**  | `layer_weight_scaling` | `float`   | `0.5`             | Layer weight scaling factor (0.0-1.0). Lower values = less outer layer fuzzing |
|              | `enable_layer_weight_scaling` | `bool` | `True`        | Enable/disable layer weight scaling             |

### Layer Weight Scaling

Layer weight scaling allows fine-tuned control over mutation distribution across protocol layers:

- **Lower values (0.1)**: Focus mutations on inner layers (payloads), minimize header fuzzing
- **Higher values (0.9)**: Distribute mutations more evenly across all layers  
- **Formula**: `effective_weight = base_weight × (scaling_factor ^ depth_below_surface)`

**Example Usage:**
```python
class WebAppFuzzCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.layer_weight_scaling = 0.1  # Focus on HTTP payload, not IP/TCP headers
        self.enable_layer_weight_scaling = True
        
    def get_packet(self):
        return IP(dst="192.168.1.100") / TCP(dport=80) / Raw("HTTP data")
```

**Validation Results**: TCP fields show 93-95% reduction in mutations with 0.1 vs 0.9 scaling.  
**Documentation**: See `LAYER_WEIGHT_SCALING.md` for comprehensive details and edge cases.

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
#### Default mappings provided with the application
The default_mappings.py file contains the default dictionary and weights, these should be halfway sane defaults that work for most fuzzing.
```python
default_field_mappings = {
    "TCP.dport": ["fuzzdb/wordlists-misc/common-ports.txt"],
    "Raw.load": ["fuzzdb/attack-payloads/all-attacks/all-attacks-unix.txt"],
    "DNS.qname": ["fuzzdb/discovery/dns/dns-names.txt"]
}
```
#### User provided mappings file
Anything set within a campaing effects only that campaing, unless a child campaign is created from it.
```python
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
```
```python
class WebAppCampaign(FuzzingCampaign):
    name = "Custom Dictionary Campaign"
    target = "192.168.1.100"
    dictionary_config_file = "examples/config/user_dictionary_config.py"  # Campaign-specific
    
    packet = IP() / TCP() / HTTP() / HTTPRequest(
        Path=b"/",
        Method=b"GET",
        dictionaries=["custom/web-ports.txt"]  # Highest priority - field-specific
    )
```
#### Override in campaign defniition
```python
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

#### User provided dicitonary on commandline
This applies to all campaings that are ran
```bash
packetfuzz examples/basic/01_quick_start.py --dictionary-config examples/config/user_dictionary_config.py
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


## Network Interface Offload Management

When fuzzing with malformed packets, network interface offload features, both those implemented in drivers, firmware and hardware can interfere by automatically "fixing" corrupted checksums, segmentation, and other intentionally malformed packet attributes before transmission. PacketFuzz provides automatic netowork interface configuration to disable these features during fuzzing campaigns. By default it will restore the previous settings when it exits.

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


## Advanced Features

### Callback System Architecture

The framework provides 6 callback types for comprehensive monitoring and custom logic integration. These callbacks can be optionally implemented in a campaign by the user. When provided they are caled at various points throughout the fuzz campaing execution.

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

#### Callback Return Values

| Return Value | Description | Effect |
|--------------|-------------|--------|
| `SUCCESS` | Normal execution | Continue to next step |
| `NO_SUCCESS` | This indicates that the callback did not execute correctly, but that it does not indicate a crash or target failure
| `FAIL_CRASH` | This indicates a target failure, when this is returned the crash callback handler will be executed

#### Callback Implementation Pattern

```python
from fuzzing_framework import FuzzingCampaign, CallbackResult

class CallbackDemoCampaign(FuzzingCampaign):
    name = "Callback Demo"
    target = "192.168.1.100"
    
    def my_pre_launch_callback(self, context):
        """Validate target before starting campaign"""
        print(f"Validating target: {self.target}")
        # Return SUCCESS or NO_SUCCESS
        return CallbackResult.SUCCESS
    
    def my_pre_send_callback(self, packet, context):
        """Modify packet before sending"""
        print(f"Sending: {packet.summary()}")
        return CallbackResult.SUCCESS, packet  # Modified packet
    
    def my_post_send_callback(self, packet, response, context):
        """Analyze response after sending"""
        if response:
            print(f"Response: {response.summary()}")
        return CallbackResult.SUCCESS
    
    def my_crash_callback(self, packet, error, context):
        """Handle crashes and errors"""
        print(f"Crash detected: {error}")
        # Log to file, save packet, etc.
        return CallbackResult.SUCCESS
    
    def my_monitor_callback(self, context):
        """Continuous monitoring during campaign"""
        print(f"Progress: {context.get('packets_sent', 0)} packets sent")
        return CallbackResult.SUCCESS
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
        IP() /
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

