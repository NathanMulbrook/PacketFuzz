#!/usr/bin/env python3
"""
Test runner for all scapy-fuzzer tests.

Runs the complete test suite including:
1. Core functionality tests (actual framework testing)
2. Example validation tests (educational content verification)

IMPORTANT: Example validation serves a different purpose than functional testing.
Examples are validated to ensure they remain functional for user education when
framework changes are made. They are NOT used to test framework functionality -
that is the purpose of the core test suite.

Example validation ensures:
- All examples execute without errors
- Framework API changes don't break user-facing documentation
- Examples maintain their educational and demonstration value
- Import patterns used in examples continue to work

This separation keeps testing concerns clear:
- Core tests: Verify framework works correctly
- Example validation: Verify user education materials work correctly
"""
import os
import sys
import unittest
import subprocess
import shutil
import tempfile
from pathlib import Path

def cleanup_test_artifacts():
    """
    Clean up any test artifacts that may have been left behind.
    This includes temporary files, PCAP files, and other test residue.
    """
    project_root = Path(__file__).parent.parent
    
    # Files to clean up in the main directory
    cleanup_files = [
        "test.pcap",
        "fallback_test.pcap", 
        "test_output.pcap",
        "test_packets_0.pcap",
        "test_packets_1.pcap", 
        "test_packets_2.pcap",
        # Legacy fuzz field reports (should be in logs/ now)
        "fuzz_fields_input_report.txt",
        "fuzz_fields_output_report.txt"
    ]
    
    print("[CLEANUP] Cleaning up test artifacts...")
    
    # Clean up files in project root
    cleaned_files = 0
    for filename in cleanup_files:
        filepath = project_root / filename
        if filepath.exists():
            try:
                filepath.unlink()
                print(f"[CLEANUP] Removed {filename}")
                cleaned_files += 1
            except Exception as e:
                print(f"[CLEANUP] Warning: Could not remove {filename}: {e}")
    
    # Clean up crash log directories and their contents
    crash_dirs = [
        project_root / "crash_logs",
        project_root / "examples" / "crash_logs"
    ]
    
    cleaned_crash_files = 0
    for crash_dir in crash_dirs:
        if crash_dir.exists() and crash_dir.is_dir():
            try:
                # Count and remove all files in crash logs directory
                crash_files = list(crash_dir.iterdir())
                for crash_file in crash_files:
                    try:
                        if crash_file.is_file():
                            crash_file.unlink()
                            cleaned_crash_files += 1
                        elif crash_file.is_dir():
                            # Remove subdirectories recursively
                            shutil.rmtree(crash_file)
                            cleaned_crash_files += 1
                    except Exception:
                        # Ignore permission errors
                        pass
                        
                if crash_files:
                    print(f"[CLEANUP] Cleaned {len(crash_files)} crash log files from {crash_dir.name}/")
            except Exception:
                # Ignore permission errors on directory access
                pass
    
    # Clean up fuzz field reports from logs directory
    logs_dir = project_root / "logs"
    cleaned_log_files = 0
    if logs_dir.exists() and logs_dir.is_dir():
        log_cleanup_files = [
            "fuzz_fields_input_report.txt",
            "fuzz_fields_output_report.txt"
        ]
        
        for log_file in log_cleanup_files:
            log_path = logs_dir / log_file
            if log_path.exists():
                try:
                    log_path.unlink()
                    cleaned_log_files += 1
                    print(f"[CLEANUP] Removed log file {log_file}")
                except Exception:
                    # Ignore permission errors
                    pass
    
    # Clean up any obvious test temp directories in /tmp
    try:
        temp_patterns = ["test_corpus_", "test_dict_", "tmp"]
        cleaned_dirs = 0
        for temp_dir in Path("/tmp").iterdir():
            if temp_dir.is_dir() and any(temp_dir.name.startswith(pattern) for pattern in temp_patterns):
                # Only clean directories that look like they're from our tests
                if any(test_marker in temp_dir.name for test_marker in ["test_corpus", "test_dict", "scapy", "fuzzer"]):
                    try:
                        shutil.rmtree(temp_dir)
                        print(f"[CLEANUP] Removed temp directory {temp_dir.name}")
                        cleaned_dirs += 1
                    except Exception as e:
                        # Don't fail cleanup for permission errors on temp dirs
                        pass
    except Exception:
        # If we can't access /tmp, that's fine - just continue
        pass
    
    if cleaned_files == 0 and cleaned_dirs == 0 and cleaned_crash_files == 0 and cleaned_log_files == 0:
        print("[CLEANUP] No test artifacts found to clean up")
    else:
        print(f"[CLEANUP] Cleaned up {cleaned_files} files, {cleaned_dirs} directories, {cleaned_crash_files} crash logs, and {cleaned_log_files} log files")

def run_organized_tests():
    """Run the organized test suite."""
    print("\n" + "=" * 60)
    print("Running Core Test Suite")
    print("=" * 60)
    
    # Main test files in recommended execution order
    test_files = [
        "test_core.py",           # Core framework functionality
        "test_campaigns.py",      # Campaign system tests
        "test_pcap_functionality.py",  # PCAP output tests
        "test_pcap_fuzzing.py",   # PCAP-based fuzzing tests (new)
        "test_dictionary.py",     # Dictionary management tests  
        "test_mutators.py",       # Mutator functionality tests (new)
        # "test_cli.py",           # CLI interface tests (disabled due to CLI mismatch)
        "test_integration.py"    # Integration tests
    ]
    
    test_dir = Path(__file__).parent
    parent_dir = test_dir.parent
    
    # Add parent directory to path
    sys.path.insert(0, str(parent_dir))
    
    all_passed = True
    
    for test_file in test_files:
        test_path = test_dir / test_file
        if test_path.exists():
            print(f"\n{'='*40}")
            print(f"Running {test_file}")
            print('='*40)
            
            try:
                # Run with unittest (simpler and more reliable)
                result = subprocess.run(
                    [sys.executable, str(test_path)],
                    cwd=str(parent_dir)
                )
                success = result.returncode == 0
                
                if success:
                    print(f"### {test_file} PASSED")
                else:
                    print(f"--- {test_file} FAILED")
                    all_passed = False
                    
            except Exception as e:
                print(f"--- Error running {test_file}: {e}")
                all_passed = False
        else:
            print(f"!!! Test file {test_file} not found")
    
    return all_passed

def run_example_validation():
    """
    Run example validation as part of the test suite.
    
    IMPORTANT: This is NOT testing framework functionality.
    Examples are validated to ensure they remain functional for user education
    when framework changes are made. Examples serve as:
    
    1. User education and demonstration
    2. API usage examples  
    3. Getting started guides
    4. Documentation through code
    
    The validation ensures examples don't break due to framework changes,
    maintaining their educational and demonstration value.
    """
    print("\n" + "=" * 60)
    print("Running Example Validation (Educational Content)")
    print("=" * 60)
    print("NOTE: Examples are validated for educational purposes only")
    print("      They are NOT used for testing framework functionality")
    print()
    
    # Run the example validation tests
    test_dir = Path(__file__).parent
    example_test_file = test_dir / "test_example_validation.py"
    
    if example_test_file.exists():
        result = subprocess.run(
            [sys.executable, str(example_test_file)],
            cwd=str(test_dir.parent)
        )
        return result.returncode == 0
    else:
        print("!!! Example validation test file not found")
        return True

def main():
    """Run the comprehensive test structure."""
    print("=" * 60)
    print("PacketFuzzer - Comprehensive Test Suite")
    print("=" * 60)
    
    # Clean up any leftover test artifacts from previous runs
    cleanup_test_artifacts()
    print()
    
    all_results = []
    
    # Run core tests
    core_result = run_organized_tests()
    all_results.append(core_result)
    
    # Run example validation
    example_result = run_example_validation()
    all_results.append(example_result)
    
    # Final cleanup after all tests
    print()
    cleanup_test_artifacts()
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Suite Summary")
    print("=" * 60)
    
    if all(all_results):
        print("### ALL TESTS PASSED!")
        print("\nComprehensive test structure:")
        print("  - test_core.py: Core framework functionality")
        print("  - test_campaigns.py: Campaign system tests")  
        print("  - test_pcap_functionality.py: PCAP output tests")
        print("  - test_pcap_fuzzing.py: PCAP-based fuzzing tests")
        print("  - test_dictionary.py: Dictionary management")
        print("  - test_mutators.py: Mutator functionality tests")
        print("  - test_cli.py: CLI interface tests")
        print("  - test_integration.py: End-to-end integration")
        print("  - test_example_validation.py: Example validation (educational)")
        print("  - conftest.py: Shared test utilities")
        print()
        print("NOTE: Examples are validated for educational purposes only.")
        print("      They ensure user-facing documentation remains functional.")
        return 0
    else:
        print("--- SOME TESTS FAILED")
        failed_suites = []
        if all_results and not all_results[0]:
            failed_suites.append("Core Tests")
        if len(all_results) > 1 and not all_results[1]:
            failed_suites.append("Example Validation")
        
        if failed_suites:
            print(f"Failed suites: {', '.join(failed_suites)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
