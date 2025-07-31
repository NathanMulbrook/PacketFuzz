# Basic Examples

This directory contains beginner-friendly examples that introduce core concepts of the Scapy Fuzzing Framework. These examples are designed to be run in order for the best learning experience.

## Examples Overview

### 01_quick_start.py
**Your First Fuzzing Campaign**
- Basic TCP port fuzzing
- Simple packet construction
- Default configuration usage
- Essential concepts introduction

**What you'll learn:**
- How to create a fuzzing campaign
- Basic packet construction with Scapy
- Running campaigns with iterations
- Understanding campaign output

### 02_campaign_types.py  
**Different Protocol Fuzzing**
- HTTP web application fuzzing
- DNS infrastructure testing
- TCP port scanning
- Multiple target configurations

**What you'll learn:**
- Protocol-specific fuzzing techniques
- Different packet types and structures
- Target specification methods
- Rate limiting and timing control

### 03_pcap_basics.py
**PCAP-Based Regression Testing**
- Loading existing network captures
- Regression testing methodology
- Layer-specific targeting
- Response analysis basics

**What you'll learn:**  
- PCAP file integration
- Regression vs. mutation fuzzing
- Layer extraction concepts
- Basic response handling

## Running the Examples

### Sequential Learning (Recommended)
```bash
python3 examples/basic/01_quick_start.py
python3 examples/basic/02_campaign_types.py  
python3 examples/basic/03_pcap_basics.py
```

### Individual Examples
```bash
# Run specific example
python3 examples/basic/01_quick_start.py

# With verbose output
python3 examples/basic/02_campaign_types.py --verbose
```

## Prerequisites

- Basic Python knowledge
- Understanding of network protocols (helpful but not required)
- Scapy library installed
- Network permissions for packet sending

## Key Concepts Covered

### Campaign Structure
- Inheriting from `FuzzingCampaign`
- Setting target addresses
- Defining packet templates
- Configuring iteration limits

### Packet Construction
- Basic Scapy packet building
- Layer composition (IP/TCP/UDP)
- Payload configuration
- Port and address specification

### Fuzzing Modes
- Dictionary-based fuzzing
- Field-specific targeting
- Rate limiting
- Response capture

### PCAP Integration
- Loading existing captures
- Regression testing
- Layer extraction
- Payload analysis

## Common Issues

### Permission Errors
Some examples require network permissions:
```bash
sudo python3 examples/basic/01_quick_start.py
```

### Target Unreachable
Examples use localhost by default. If issues occur:
- Check firewall settings
- Verify target addresses
- Use `--dry-run` for testing

### Missing Dependencies
Ensure all requirements are installed:
```bash
pip install -r requirements.txt
```

## Learning Path

1. **Start Here**: `01_quick_start.py`
   - Understand basic campaign structure
   - Learn essential concepts
   - Get familiar with output format

2. **Expand Knowledge**: `02_campaign_types.py`
   - Explore different protocols
   - Learn target specification
   - Understand rate limiting

3. **Advanced Techniques**: `03_pcap_basics.py`
   - PCAP file integration
   - Regression testing concepts
   - Layer-specific fuzzing

4. **Next Steps**: Move to `../advanced/` examples
   - Complex configurations
   - Callback systems
   - Advanced PCAP techniques

## Tips for Beginners

### Understanding Output
- `📦` indicates packet being sent
- `📨` shows responses received
- `⏰` indicates timeouts
- `✅` shows successful operations

### Modifying Examples
- Change target addresses to your test environment
- Adjust iteration counts for testing
- Experiment with different packet types
- Try various rate limits

### Debugging
- Use `print()` statements to understand flow
- Check packet construction with `.show()`
- Verify target connectivity first
- Start with small iteration counts

## Next Steps

After completing these basic examples:

1. **Explore Advanced Examples** (`../advanced/`)
   - Complex campaign configurations
   - Callback system usage
   - Advanced PCAP techniques

2. **Try Interactive Demos** (`../demos/`)
   - Callback system exploration
   - PCAP fuzzing demonstration

3. **Create Your Own Campaigns**
   - Use examples as templates
   - Customize for your specific needs
   - Contribute back to the project

## Support

- Review the main project README.md
- Check FRAMEWORK_DOCUMENTATION.md for API details
- Run the test suite to verify installation
- Create issues for questions or bugs
