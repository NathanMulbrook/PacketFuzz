# Scapy Fuzzer Examples

# Examples Directory

This directory contains educational examples demonstrating the scapy-fuzzer framework. Examples are organized in a progressive learning structure from simple to advanced usage.

## Testing and Validation

All examples are integrated into the main test suite for validation purposes. This ensures that:

- ✅ **Examples Always Work**: All examples are validated with every test run
- ✅ **API Compatibility**: Framework changes that break examples are caught immediately  
- ✅ **Educational Quality**: Examples remain useful for learning and demonstration
- ✅ **Import Validation**: All import statements and dependencies are verified

**Important Note**: Examples are validated for educational purposes only - they are NOT used for testing framework functionality. The test suite maintains a clear separation between:

- **Functional Tests**: Test the framework's core capabilities and correctness
- **Example Validation**: Verify examples work properly as educational content

### Running Example Validation

Examples are automatically validated when you run the full test suite:

```bash
# Run all tests including example validation
python3 tests/run_all_tests.py

# Run only example validation
python3 tests/test_example_validation.py
```

### Expected Example Behavior

Most examples require network privileges and will fail with "Root privileges required" when run as non-root users. This is expected behavior and doesn't indicate broken examples - it validates that:

1. Examples execute without import/syntax errors
2. Framework API calls are correct
3. Educational content is properly structured
4. Configuration examples parse correctly

### Example Categories Validated

- **Basic Examples** (5): Quick start, FuzzField basics, PCAP output
- **Intermediate Examples** (4): Inheritance, dictionaries, regression, callbacks  
- **Advanced Examples** (2): Complex campaigns, PCAP analysis
- **Configuration Examples** (2): Network configs, webapp configs

## Directory Structure

### `basic/` - Minimal Effort Fuzzing
Simple examples to get started quickly with minimal configuration.

- **`01_quick_start.py`** - Absolute minimal fuzzing example (5 lines of config)
- **`02_fuzzfield_basics.py`** - Basic FuzzField usage with different value types
- **`03_pcap_output.py`** - Simple PCAP file generation and analysis

### `intermediate/` - Moderate Complexity
Examples showing framework features with moderate configuration complexity.

- **`01_campaign_inheritance.py`** - Campaign class inheritance patterns
- **`02_dictionary_config.py`** - Dictionary configuration and overrides
- **`03_pcap_regression.py`** - PCAP-based regression testing
- **`04_callback_basics.py`** - Basic callback system usage

### `advanced/` - Complex Scenarios
Advanced examples demonstrating full framework capabilities.

- **`01_custom_mutators.py`** - Custom mutator implementation and integration
- **`02_callback_systems.py`** - Complete callback system with error handling
- **`03_pcap_analysis.py`** - Advanced PCAP analysis and layer extraction

### `config/` - Configuration Files
Reusable configuration files for examples.

- **`user_dictionary_config.py`** - Example dictionary configuration

## Running Examples

### Command Line Interface
```bash
# Run basic examples
python examples/basic/01_quick_start.py
python examples/basic/02_fuzzfield_basics.py

# Run intermediate examples
python examples/intermediate/01_campaign_inheritance.py

# Run advanced examples with CLI
scapy-fuzzer examples/advanced/01_custom_mutators.py --verbose
```

### Programmatic Usage
```python
# Import and run campaigns directly
from examples.basic.quick_start import QuickStartCampaign
campaign = QuickStartCampaign()
campaign.execute()
```

## Feature Coverage

| Feature | Basic | Intermediate | Advanced |
|---------|-------|--------------|----------|
| FuzzField | ✓ | ✓ | ✓ |
| Campaign Classes | ✓ | ✓ | ✓ |
| PCAP Output | ✓ | ✓ | ✓ |
| Dictionary Config | | ✓ | ✓ |
| Callbacks | | ✓ | ✓ |
| Custom Mutators | | | ✓ |
| Layer Extraction | | ✓ | ✓ |
| Error Handling | | | ✓ |

## Design Principles

- **Minimal Effort**: Basic examples require minimal configuration (3-5 lines)
- **Progressive Complexity**: Each level builds on the previous
- **Consistent Styling**: All examples follow the same code patterns
- **Real-World Focus**: Examples solve actual fuzzing problems
- **Self-Contained**: Each example runs independently

## Getting Started

### 1. Quick Start (Recommended)
Run the examples in order for the best learning experience:

```bash
# Run all examples in sequence
python3 examples/run_all_examples.py

# Or run specific categories
python3 examples/basic/01_quick_start.py
python3 examples/basic/02_campaign_types.py
python3 examples/basic/03_pcap_basics.py
```

### 2. Basic Examples (`basic/`)
Perfect for beginners learning the framework:

- **01_quick_start.py** - Your first fuzzing campaign
- **02_campaign_types.py** - HTTP, DNS, and TCP fuzzing
- **03_pcap_basics.py** - PCAP-based regression testing

### 3. Advanced Examples (`advanced/`)
Complex scenarios for experienced users:

- **01_complex_campaigns.py** - Callbacks, inheritance, and advanced configuration
- **02_pcap_analysis.py** - Advanced PCAP fuzzing and layer analysis

### 4. Interactive Demos (`demos/`)
Hands-on demonstrations of specific features:

- **callback_system_demo.py** - Callback system exploration
- **pcap_fuzzing_demo.py** - PCAP fuzzing capabilities

### 5. Utilities (`utils/`)
Helper scripts for testing and setup:

- **create_sample_pcaps.py** - Generate sample PCAP files

### 6. Legacy Examples
Maintained for backward compatibility with older tutorials and documentation.

## Learning Path

### For Beginners
1. Start with `basic/01_quick_start.py`
2. Explore different protocols in `basic/02_campaign_types.py`
3. Learn PCAP basics with `basic/03_pcap_basics.py`
4. Try interactive demos in `demos/`

### For Experienced Users
1. Jump to `advanced/` examples
2. Study complex callback patterns
3. Explore advanced PCAP techniques
4. Create custom campaigns based on examples

## Running Examples

### Individual Examples
```bash
cd /path/to/scapy-fuzzer
python3 examples/basic/01_quick_start.py
```

### All Examples
```bash
cd /path/to/scapy-fuzzer
python3 examples/run_all_examples.py
```

### Specific Category
```bash
# Run only basic examples
python3 examples/basic/01_quick_start.py
python3 examples/basic/02_campaign_types.py
python3 examples/basic/03_pcap_basics.py
```

## Prerequisites

- Python 3.10+
- Scapy library
- Network permissions (for sending packets)
- Sample PCAP files (generated automatically if missing)

## Common Issues

### Permission Errors
```bash
# Run with appropriate network permissions
sudo python3 examples/basic/01_quick_start.py
```

### Missing PCAP Files
The framework includes sample PCAP files. If missing, run:
```bash
python3 examples/utils/create_sample_pcaps.py
```

### Import Errors
Ensure you're running from the project root directory:
```bash
cd /path/to/scapy-fuzzer
python3 examples/basic/01_quick_start.py
```

## Legacy Examples

The following examples demonstrate current framework features:

- `embedded_config_examples.py` - Examples using method-based configuration
- `fuzzfield_demo.py` - Demonstration of FuzzField capabilities  
- `pcap_output_demo.py` - PCAP output demonstration
- `quick_start_example.py` - Basic getting started tutorial
- `user_dictionary_config.py` - User-defined dictionary configuration

## Creating Your Own Campaigns

1. Create a new Python file
2. Import `FuzzingCampaign` from `fuzzing_framework`
3. Define your campaign class by inheriting from `FuzzingCampaign`
4. Configure packet, target, and other attributes
5. Add to `CAMPAIGNS` list at the end of your file

Example:

```python
from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP

class MyCampaign(FuzzingCampaign):
    name = "My Test Campaign"
    target = "192.168.1.1"
    packet = IP(dst="192.168.1.1") / TCP(dport=FuzzField(80, values=[80, 443, 8080]))
    iterations = 100

CAMPAIGNS = [MyCampaign]
```

## Contributing Examples

When adding new examples:

1. **Choose the right category** (basic/advanced/demos)
2. **Follow naming conventions** (numbered for basic/advanced)
3. **Include comprehensive documentation**
4. **Add to run_all_examples.py**
5. **Test thoroughly before submitting**

## Support

- Check the main README.md for framework documentation
- Review FRAMEWORK_DOCUMENTATION.md for API details
- Run tests with `python3 tests/run_all_tests.py`
- Create issues for bugs or feature requests

# Configuration Changes

- Remove `skip_simple_fields` from all campaign defaults, configs, and examples
- Only use `simple_field_fuzz_weight` for configuration and documentation
