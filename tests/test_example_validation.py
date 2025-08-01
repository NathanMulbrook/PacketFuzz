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
    
    def run_campaign_cli(self, campaign_path, timeout=30, allow_failure=False):
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
            [sys.executable, str(self.project_root / "packetfuzz.py"), str(campaign_path), "--dry-run"],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        success = result.returncode == 0
        if not success and not allow_failure:
            self.fail(f"{campaign_path.name} failed with return code {result.returncode}:\n"
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
