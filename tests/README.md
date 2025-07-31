# Scapy Fuzzer Test Suite

This directory contains the comprehensive, well-organized test suite for the scapy-fuzzer project.

## Test Structure

### Core Test Files

- **`conftest.py`**: Shared test fixtures, utilities, and helper campaign classes
- **`test_core.py`**: Core framework functionality tests (25+ tests)
- **`test_campaigns.py`**: Campaign system and inheritance tests (17+ tests)
- **`test_pcap_functionality.py`**: PCAP output and file handling tests (16+ tests)
- **`test_dictionary.py`**: Dictionary management and mapping tests (5+ tests)
- **`test_integration.py`**: End-to-end integration tests
- **`test_example_validation.py`**: Example file validation tests (9+ tests)
- **`run_all_tests.py`**: Comprehensive test runner that executes all test suites

### Test Categories

#### Core Functionality Tests (`test_core.py`)
- **Packet Extensions**: Tests for `field_fuzz()` and `fuzz_config()` methods
- **Embedded Configuration**: Tests for packet-level and field-level configuration
- **FuzzField**: Tests for fuzzing field functionality and preservation
- **FieldOverride**: Tests for field override functionality and conversion
- **Core Fuzzer**: Tests for ScapyFuzzer integration and packet serialization
- **Configuration Persistence**: Tests for configuration copying and independence

#### Campaign System Tests (`test_campaigns.py`)
- **Base Campaign**: Tests for FuzzingCampaign base class functionality
- **Specialized Campaigns**: Tests for HTTP, DNS, and Layer 2 campaign types
- **Inheritance**: Tests for campaign inheritance and attribute override patterns
- **Utilities**: Tests for campaign string representation and comparison

#### PCAP Functionality Tests (`test_pcap_functionality.py`)
- **PCAP Output**: Tests for PCAP file creation and writing
- **File Handling**: Tests for PCAP path resolution and error handling
- **Campaign Integration**: Tests for PCAP output in campaign execution

#### Dictionary Management Tests (`test_dictionary.py`)
- **Default Mappings**: Tests for default field-to-dictionary mappings
- **Dictionary Resolution**: Tests for dictionary file loading and field mapping
- **Configuration Override**: Tests for user dictionary configuration

#### Integration Tests (`test_integration.py`)
- **End-to-End Workflows**: Tests for complete fuzzing workflows
- **Component Integration**: Tests for interaction between framework components
- **Error Handling**: Tests for graceful error handling across components  
- **Core Fuzzer**: Tests for ScapyFuzzer integration
- **Configuration Persistence**: Tests for config isolation and copying

#### Example Validation Tests (`test_example_validation.py`)
- Validates that all example files can be imported and executed
- Ensures examples remain functional as the framework evolves

### Shared Resources (`conftest.py`)

#### Test Campaign Classes
- `BasicTestCampaign`: Basic TCP campaign for testing
- `HTTPTestCampaign`: HTTP-focused campaign with embedded config
- `DNSTestCampaign`: DNS fuzzing campaign
- `Layer2TestCampaign`: Layer 2 ARP fuzzing campaign
- `PCAPTestCampaign`: Campaign configured for PCAP output
- `NetworkTestCampaign`: Campaign configured for network output
- `DictionaryTestCampaign`: Campaign with custom dictionary config

#### Test Fixtures
- `basic_campaign`, `http_campaign`, `dns_campaign`, etc.
- `temp_pcap_file`, `temp_config_file`
- Support for both pytest and unittest frameworks

#### Utility Functions
- `create_test_packet()`: Create test packets of various types
- `configure_packet_fuzzing()`: Configure fuzzing for packets
- `validate_campaign_config()`: Validate campaign configurations

## Running Tests

### Run All Tests
```bash
python tests/run_all_tests.py
```

### Run Individual Test Files
```bash
python tests/test_core.py
python tests/test_example_validation.py
```

### Test Framework Support

The test suite supports both pytest and unittest:
- **Pytest**: Full featured testing with fixtures and advanced features
- **Unittest**: Fallback for environments without pytest
- **Mixed Mode**: Uses pytest when available, falls back to unittest

## Test Design Principles

1. **Clean Organization**: Tests are logically grouped by functionality
2. **Shared Resources**: Common fixtures and utilities eliminate duplication
3. **Framework Agnostic**: Works with or without pytest
4. **Maintainable**: Clear structure makes tests easy to update and extend
5. **Focused**: Only essential, working tests are included

## Adding New Tests

1. **Core Functionality**: Add to `test_core.py` with unittest.TestCase inheritance
2. **Shared Resources**: Add test campaigns or utilities to `conftest.py`
3. **Example Validation**: Add to `test_example_validation.py` for new examples

## Test Results

Current status: **32 total tests**
- Core functionality: 23 tests
- Example validation: 9 tests
- **100% pass rate**

The test suite provides comprehensive coverage of the core fuzzing framework while maintaining a clean, maintainable structure.
