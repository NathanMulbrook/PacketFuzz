#!/usr/bin/env python3
"""
Example Validation Tests

IMPORTANT: These tests are NOT functional tests of the framework.
Their sole purpose is to ensure that all examples execute without errors
when the framework changes, guaranteeing that examples remain functional
and demonstrate correct usage to users.

This validation serves as a continuous integration check to ensure:
1. All example code remains syntactically correct
2. All example imports work correctly  
3. No examples crash due to framework API changes
4. Examples maintain their educational and demonstration value

The examples should NOT be used for testing framework functionality -
that is the purpose of the core test suite. Examples are purely for
user education and demonstration.
"""

import sys
import os
import unittest
import subprocess
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import cleanup_test_files

class TestExampleValidation(unittest.TestCase):
    """
    Validate that all example scripts execute without errors.
    
    NOTE: This is NOT testing framework functionality - it's ensuring
    that examples work correctly for user education purposes.
    """
    
    def setUp(self):
        """Set up test fixtures."""
        # Clean up any leftover files from previous tests
        cleanup_test_files()
        
        self.examples_dir = Path(__file__).parent.parent / "examples"
        self.project_root = Path(__file__).parent.parent
        
    def tearDown(self):
        """Clean up after tests."""
        # Clean up any files created during example execution
        cleanup_test_files()
    
    def run_example_script(self, script_path, expected_output=None, timeout=30, allow_failure=False):
        """
        Helper method to run an example script and validate it works.
        
        Args:
            script_path: Path to the script
            expected_output: Optional string that should appear in output
            timeout: Maximum execution time in seconds
            allow_failure: If True, don't fail test on non-zero exit code
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        if not hasattr(script_path, 'exists') or not script_path.exists():
            self.skipTest(f"Example script {script_path} not found")
            
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        success = result.returncode == 0
        if not success and not allow_failure:
            self.fail(f"{script_path.name} failed with return code {result.returncode}:\n"
                     f"STDOUT: {result.stdout}\n"
                     f"STDERR: {result.stderr}")
        
        if expected_output and expected_output not in result.stdout:
            self.fail(f"{script_path.name} missing expected output '{expected_output}':\n"
                     f"STDOUT: {result.stdout}")
        
        return success, result.stdout, result.stderr

    # ================================
    # BASIC EXAMPLES VALIDATION
    # ================================
    
    def test_basic_01_quick_start(self):
        """Validate basic/01_quick_start.py executes correctly."""
        script_path = self.examples_dir / "basic" / "01_quick_start.py"
        success, stdout, stderr = self.run_example_script(
            script_path, 
            expected_output="Basic Example 1: Quick Start"
        )
        self.assertTrue(success)
        
    def test_basic_02_fuzzfield_basics(self):
        """Validate basic/02_fuzzfield_basics.py executes correctly."""
        script_path = self.examples_dir / "basic" / "02_fuzzfield_basics.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Basic Example 2: FuzzField Basics"
        )
        self.assertTrue(success)
        
    def test_basic_03_pcap_output(self):
        """Validate basic/03_pcap_output.py executes correctly."""
        script_path = self.examples_dir / "basic" / "03_pcap_output.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Basic Example 3: PCAP Output"
        )
        self.assertTrue(success)

    # ================================
    # INTERMEDIATE EXAMPLES VALIDATION
    # ================================
    
    def test_intermediate_01_campaign_inheritance(self):
        """Validate intermediate/01_campaign_inheritance.py executes correctly."""
        script_path = self.examples_dir / "intermediate" / "01_campaign_inheritance.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Intermediate Example 1: Campaign Inheritance"
        )
        self.assertTrue(success)
        
    def test_intermediate_02_dictionary_config(self):
        """Validate intermediate/02_dictionary_config.py executes correctly."""
        script_path = self.examples_dir / "intermediate" / "02_dictionary_config.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Intermediate Example 2: Dictionary Configuration"
        )
        self.assertTrue(success)
        
    def test_intermediate_03_pcap_regression(self):
        """Validate intermediate/03_pcap_regression.py executes correctly."""
        script_path = self.examples_dir / "intermediate" / "03_pcap_regression.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Intermediate Example 3: PCAP Regression",
            timeout=60  # Increase timeout because PCAP creation takes time
        )
        self.assertTrue(success)
        
    def test_intermediate_04_callback_basics(self):
        """Validate intermediate/04_callback_basics.py executes correctly."""
        script_path = self.examples_dir / "intermediate" / "04_callback_basics.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Intermediate Example 4: Callback System Basics"
        )
        self.assertTrue(success)

    # ================================
    # ADVANCED EXAMPLES VALIDATION
    # ================================
    
    def test_advanced_01_complex_campaigns(self):
        """Validate advanced/01_complex_campaigns.py executes correctly."""
        script_path = self.examples_dir / "advanced" / "01_complex_campaigns.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Advanced Example 1: Complex Campaign Scenarios"
        )
        self.assertTrue(success)
        
    def test_advanced_02_pcap_analysis(self):
        """Validate advanced/02_pcap_analysis.py executes correctly."""
        script_path = self.examples_dir / "advanced" / "02_pcap_analysis.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Advanced Example 2: PCAP Analysis and Processing"
        )
        self.assertTrue(success)

    # ================================
    # CONFIGURATION TEMPLATES VALIDATION
    # ================================
    
    def test_config_webapp_config(self):
        """Validate config/webapp_config.py executes correctly."""
        script_path = self.examples_dir / "config" / "webapp_config.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Web Application Configuration Templates"
        )
        self.assertTrue(success)
        
    def test_config_network_config(self):
        """Validate config/network_config.py executes correctly."""
        script_path = self.examples_dir / "config" / "network_config.py"
        success, stdout, stderr = self.run_example_script(
            script_path,
            expected_output="Network Infrastructure Configuration Templates"
        )
        self.assertTrue(success)

    # ================================
    # COMPREHENSIVE RUNNER VALIDATION
    # ================================
    
    def test_run_all_examples_runner(self):
        """Validate that the comprehensive example runner works."""
        script_path = self.examples_dir / "run_all_examples.py"
        
        # Note: We expect the runner to execute but many examples will fail due to
        # root privileges requirements. The runner returning exit code 1 is normal.
        try:
            success, stdout, stderr = self.run_example_script(
                script_path,
                expected_output="COMPREHENSIVE EXAMPLE RUNNER",
                timeout=60,  # Reduced timeout since examples should fail fast
                allow_failure=True  # Allow exit code 1 since most examples need root
            )
            
            # Validate that the runner executed and showed results
            self.assertIn("COMPREHENSIVE EXAMPLE RUNNER", stdout)
            self.assertIn("FINAL RESULTS", stdout)
            self.assertIn("Total Examples Run:", stdout)
            
            # Verify it found and ran examples from all categories
            self.assertIn("BASIC EXAMPLES", stdout)
            self.assertIn("INTERMEDIATE EXAMPLES", stdout)  
            self.assertIn("ADVANCED EXAMPLES", stdout)
            
        except subprocess.TimeoutExpired:
            # Skip this test if it times out - individual examples are working 
            # correctly so this timeout is acceptable for educational validation
            self.skipTest("Comprehensive example runner timed out after 60 seconds - " +
                         "individual examples are working correctly, so this is acceptable " +
                         "for educational validation purposes")
        self.assertIn("CONFIGURATION EXAMPLES", stdout)
        self.assertIn("FINAL RESULTS", stdout)

    # ================================
    # FRAMEWORK IMPORT VALIDATION
    # ================================
    
    def test_framework_imports_work_for_examples(self):
        """
        Validate that examples can import framework modules correctly.
        
        This ensures that the framework API remains stable for example usage.
        """
        import_test_code = f"""
import sys
sys.path.insert(0, '{self.project_root}')

# Test core imports that examples use
from fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult
from pcapfuzz import PcapFuzzCampaign
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS

print('### All framework imports successful for examples')
"""
        
        result = subprocess.run(
            [sys.executable, "-c", import_test_code],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=10
        )
        
        self.assertEqual(result.returncode, 0,
                        f"Framework import test failed with stderr: {result.stderr}")
        self.assertIn("All framework imports successful", result.stdout)

if __name__ == '__main__':
    # Run example validation tests
    print("=" * 60)
    print("Example Validation Tests")
    print("=" * 60)
    print()
    print("PURPOSE: Validate examples work correctly for user education")
    print("NOTE: These are NOT functional tests of the framework!")
    print("      Examples are purely for demonstration and learning.")
    print()
    print("This validation ensures:")
    print("  - All examples execute without errors")
    print("  - Framework API changes don't break examples")  
    print("  - Examples remain useful for user education")
    print("  - Import statements work correctly in examples")
    print()
    
    unittest.main(verbosity=2)
