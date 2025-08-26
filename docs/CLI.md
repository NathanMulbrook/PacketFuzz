# PacketFuzz CLI Reference

This document provides a comprehensive reference for the PacketFuzz command-line interface.

## Basic Usage

```bash
python -m packetfuzz [campaign_file] [options]
```

## Campaign Execution

### Campaign File
```bash
python -m packetfuzz examples/basic/http_fuzz.py
```
Execute a campaign defined in a Python file.

### Iterations
```bash
python -m packetfuzz campaign.py --iterations 100
```
Control the number of fuzzing iterations (default: 10).

## Output Options

### Network Output
```bash
# Send packets to network (default)
python -m packetfuzz campaign.py --output-network

# Disable network output (testing mode)
python -m packetfuzz campaign.py --no-output-network
```

### PCAP Output
```bash
# Save all packets to PCAP file
python -m packetfuzz campaign.py --pcap-file output.pcap

# Environment variable alternative
export PACKETFUZZ_PCAP_FILE="output.pcap"
python -m packetfuzz campaign.py
```

### Report Formats

PacketFuzz supports multiple report output formats for campaign results:

#### Single Format
```bash
# Generate HTML report
python -m packetfuzz campaign.py --report-formats html

# Generate JSON report (default)
python -m packetfuzz campaign.py --report-formats json

# Generate CSV report
python -m packetfuzz campaign.py --report-formats csv

# Generate SARIF report (for security tools)
python -m packetfuzz campaign.py --report-formats sarif

# Generate Markdown report
python -m packetfuzz campaign.py --report-formats markdown

# Generate YAML report
python -m packetfuzz campaign.py --report-formats yaml
```

#### Multiple Formats
```bash
# Generate multiple formats
python -m packetfuzz campaign.py --report-formats html json csv

# Generate all supported formats
python -m packetfuzz campaign.py --report-formats all
```

#### Environment Variable Configuration
```bash
# Configure via environment variable
export PACKETFUZZ_REPORT_FORMATS="html,json,csv"
python -m packetfuzz campaign.py

# Single format via environment
export PACKETFUZZ_REPORT_FORMATS="sarif"
python -m packetfuzz campaign.py
```

## Rate Limiting

```bash
# Limit to 10 packets per second
python -m packetfuzz campaign.py --rate-limit 10

# Environment variable alternative
export PACKETFUZZ_RATE_LIMIT="5"
python -m packetfuzz campaign.py
```

## Verbose Output

```bash
# Enable verbose logging
python -m packetfuzz campaign.py --verbose

# Environment variable alternative
export PACKETFUZZ_VERBOSE="true"
python -m packetfuzz campaign.py
```

## Dictionary Configuration

```bash
# Use custom dictionary configuration
python -m packetfuzz campaign.py --dictionary-config config.py

# Environment variable alternative
export PACKETFUZZ_DICTIONARY_CONFIG="config.py"
python -m packetfuzz campaign.py
```

## Component Checking

```bash
# Check if all required components are available
python -m packetfuzz --check-components

# Require libFuzzer to be available
python -m packetfuzz campaign.py --require-libfuzzer
```

## Environment Variables

PacketFuzz supports configuration via environment variables:

| Variable | Purpose | Default | Example |
|----------|---------|---------|---------|
| `PACKETFUZZ_PCAP_FILE` | PCAP output file | None | `output.pcap` |
| `PACKETFUZZ_REPORT_FORMATS` | Report formats (comma-separated) | `json` | `html,json,csv` |
| `PACKETFUZZ_RATE_LIMIT` | Rate limit (packets/sec) | None | `10` |
| `PACKETFUZZ_VERBOSE` | Verbose logging | `false` | `true` |
| `PACKETFUZZ_DICTIONARY_CONFIG` | Dictionary config file | None | `config.py` |

## Examples

### Basic HTTP Fuzzing with HTML Report
```bash
python -m packetfuzz examples/basic/http_fuzz.py \
    --iterations 50 \
    --report-formats html \
    --pcap-file http_fuzz.pcap
```

### Comprehensive Security Analysis
```bash
python -m packetfuzz examples/advanced/security_test.py \
    --report-formats sarif json html \
    --rate-limit 5 \
    --verbose
```

### Environment-Configured Campaign
```bash
export PACKETFUZZ_REPORT_FORMATS="all"
export PACKETFUZZ_PCAP_FILE="campaign_output.pcap"
export PACKETFUZZ_VERBOSE="true"
python -m packetfuzz examples/intermediate/protocol_fuzz.py
```

## Help and Information

```bash
# Show full help
python -m packetfuzz --help

# Check component availability
python -m packetfuzz --check-components
```

## Exit Codes

- `0`: Success
- `1`: General error (campaign failure, invalid arguments, etc.)
- `2`: Missing dependencies (when `--require-libfuzzer` is used)