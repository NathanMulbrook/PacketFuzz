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
    Validate that all campaign config files load via the packetfuzz CLI without errors.
    """
    def setUp(self):
        cleanup_test_files()
        self.examples_dir = Path(__file__).parent.parent / "examples"
        self.project_root = Path(__file__).parent.parent
        
    def tearDown(self):
        cleanup_test_files()
    
    def run_campaign_cli(self, campaign_path, timeout=120, allow_failure=False):
        """
        Helper method to run the packetfuzz CLI with a campaign config file.
        
        Args:
            campaign_path: Path to the campaign config file
            timeout: Maximum execution time in seconds
            allow_failure: If True, don't fail test on non-zero exit code
            
        Returns:
            tuple: (success, stdout, stderr)
        """
        if not hasattr(campaign_path, 'exists') or not campaign_path.exists():
            self.skipTest(f"Campaign file {campaign_path} not found")
            
        result = subprocess.run(
            [sys.executable, "-m", "packetfuzz.packetfuzz", str(campaign_path), "--disable-network", "--disable-pcap"],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Consider it a success if the CLI runs and outputs processing logs,
        # even if some campaigns within the file fail (examples may include intentionally failing cases)
        output = (result.stdout or "") + (result.stderr or "")
        # Accept config-only example files that contain no campaigns
        if "No campaigns found in configuration file" in output:
            return True, result.stdout, result.stderr
        success = ("Processing campaign" in output) and ("completed" in output or "Execution complete" in output)
        if not success and not allow_failure:
            self.fail(f"{campaign_path.name} validation did not complete as expected (rc={result.returncode}).\n"
                     f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

        return success, result.stdout, result.stderr

    def test_campaign_files_cli(self):
        """Validate all campaign config files load via packetfuzz CLI."""
        categories = ["basic", "intermediate", "advanced", "config"]
        for category in categories:
            category_dir = self.examples_dir / category
            if not category_dir.exists():
                continue
            for campaign_file in sorted(category_dir.glob("*.py")):
                with self.subTest(campaign_file=campaign_file):
                    success, stdout, stderr = self.run_campaign_cli(campaign_file)
                    self.assertTrue(success, f"{campaign_file.name} failed CLI validation")

    def test_direct_example_execution(self):
        """Validate that examples can be executed directly without errors."""
        categories = ["basic", "intermediate", "advanced"]
        skip_files = ["run_all_examples.py"]  # Skip utility files
        
        for category in categories:
            category_dir = self.examples_dir / category
            if not category_dir.exists():
                continue
            for example_file in sorted(category_dir.glob("*.py")):
                if example_file.name in skip_files:
                    continue
                    
                with self.subTest(example_file=example_file):
                    # Execute the example directly with Python
                    result = subprocess.run(
                        [sys.executable, str(example_file)],
                        cwd=str(self.project_root),
                        capture_output=True,
                        text=True,
                        timeout=30  # Shorter timeout for direct execution
                    )
                    
                    # Check if the example ran without crashing
                    # Some examples might not produce output, so we just check exit code
                    if result.returncode != 0:
                        self.fail(f"{example_file.name} failed direct execution (rc={result.returncode}).\n"
                                f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

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
