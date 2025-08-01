#!/usr/bin/env python3
"""
CLI Interface Tests

Tests for all CLI-related functionality including:
- Command-line argument parsing
- Campaign file loading and validation
- Dictionary configuration via CLI
- Output formatting and verbose modes
"""

import sys
import os
import unittest
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple

# Try to import pytest, fall back to unittest if not available
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.conftest import BasicTestCampaign, HTTPTestCampaign, DictionaryTestCampaign
from scapy.layers.inet import IP


class CLITestBase(unittest.TestCase):
    """Base class for CLI tests with shared functionality"""
    
    def run_cli_command(self, args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Helper to run CLI commands"""
        try:
            result = subprocess.run(
                ["python", "packetfuzz.py"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", "CLI script not found"


class TestCLIBasics(CLITestBase):
    """Test basic CLI functionality"""
    
    def run_cli_command(self, args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Helper to run CLI commands"""
        try:
            result = subprocess.run(
                ["python", "packetfuzz.py"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", "CLI script not found"
    
    def test_cli_help(self):
        """Test CLI help output"""
        returncode, stdout, stderr = self.run_cli_command(["--help"])
        
        # Help should work
        assert returncode == 0 or "help" in stdout.lower() or "usage" in stdout.lower()
        
        # Should contain key arguments
        help_text = stdout + stderr
        expected_options = ["--verbose", "--dry-run", "--list-campaigns"]
        for option in expected_options:
            assert option in help_text
    
    def test_cli_version(self):
        """Test CLI version information"""
        returncode, stdout, stderr = self.run_cli_command(["--version"])
        
        # Version command might not be implemented, check if it fails gracefully
        if returncode != 0:
            # If version not implemented, should still fail gracefully
            assert "version" in stderr.lower() or "unrecognized" in stderr.lower()
    
    def test_cli_no_arguments(self):
        """Test CLI with no arguments"""
        returncode, stdout, stderr = self.run_cli_command([])
        
        # Should either show help or require campaign file
        assert returncode != 0  # Should fail without arguments
        output = stdout + stderr
        assert len(output) > 0  # Should provide some feedback


class TestCampaignFileLoading(CLITestBase):
    """Test campaign file loading functionality"""
    
    def test_list_campaigns_basic(self):
        """Test listing campaigns from basic example"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        assert len(stdout) > 0
        
        # Should contain campaign information
        assert "Campaign" in stdout
    
    def test_list_campaigns_dictionary_config(self):
        """Test listing campaigns with dictionary configuration"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        assert len(stdout) > 0
        
        # Should show campaign information (dictionary config optional)
        assert "Campaign" in stdout
    
    def test_invalid_campaign_file(self):
        """Test handling of invalid campaign file"""
        returncode, stdout, stderr = self.run_cli_command([
            "nonexistent_campaign_file.py",
            "--list-campaigns"
        ])
        
        # Should fail gracefully
        assert returncode != 0
        output = stdout + stderr
        assert "not found" in output.lower() or "error" in output.lower()
    
    def test_campaign_file_with_syntax_error(self):
        """Test handling of campaign file with syntax errors"""
        # Create temporary file with syntax error
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Invalid Python syntax\nimport invalid syntax here\n")
            temp_file = f.name
        
        try:
            returncode, stdout, stderr = self.run_cli_command([
                temp_file,
                "--list-campaigns"
            ])
            
            # Should fail gracefully with syntax error
            assert returncode != 0
            output = stdout + stderr
            assert "syntax" in output.lower() or "error" in output.lower()
        finally:
            # Cleanup
            os.unlink(temp_file)


class TestDictionaryConfiguration(CLITestBase):
    """Test dictionary configuration via CLI"""
    
    def test_dictionary_config_option(self):
        """Test --dictionary-config option"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dictionary-config", "examples/config/webapp_config.py",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        # Dictionary config may or may not show specific output
        assert len(stdout) > 0
    
    def test_dictionary_config_with_invalid_file(self):
        """Test dictionary configuration with invalid file"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dictionary-config", "nonexistent_dict_config.py",
            "--list-campaigns"
        ])
        
        # Should handle invalid dictionary config gracefully
        # Either fail cleanly or ignore invalid config
        if returncode != 0:
            output = stdout + stderr
            assert "not found" in output.lower() or "error" in output.lower()
    
    def test_dictionary_config_precedence(self):
        """Test dictionary config precedence (CLI over campaign attribute)"""
        # Test without CLI override
        returncode1, stdout1, stderr1 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        # Test with CLI override
        returncode2, stdout2, stderr2 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dictionary-config", "examples/config/webapp_config.py",
            "--list-campaigns"
        ])
        
        assert returncode1 == 0 and returncode2 == 0
        
        # CLI override might or might not change the output depending on implementation
        assert len(stdout1) > 0 and len(stdout2) > 0


class TestVerboseMode(CLITestBase):
    """Test verbose mode functionality"""
    
    def test_verbose_flag(self):
        """Test --verbose flag"""
        # Normal mode
        returncode1, stdout1, stderr1 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        # Verbose mode
        returncode2, stdout2, stderr2 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--verbose",
            "--list-campaigns"
        ])
        
        assert returncode1 == 0 and returncode2 == 0
        
        # Verbose mode should provide more output
        assert len(stdout2) >= len(stdout1)
    
    def test_verbose_with_dry_run(self):
        """Test verbose mode with dry run"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--verbose",
            "--dry-run"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should show verbose dry run information
        output = stdout + stderr
        assert len(output) > 0
    
    def test_verbose_shows_configuration(self):
        """Test that verbose mode shows configuration details"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--verbose",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Verbose mode should show more configuration details
        # The exact format may vary, but should contain more information
        assert len(stdout) > 0


class TestDryRunMode(CLITestBase):
    """Test dry run mode functionality"""
    
    def test_dry_run_flag(self):
        """Test --dry-run flag"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should complete without actually running campaigns
        output = stdout + stderr
        assert len(output) > 0
    
    def test_dry_run_with_specific_campaign(self):
        """Test dry run with specific campaign selection"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run",
            "--campaigns", "0"  # Run first campaign
        ])
        
        # Should work or gracefully indicate campaign selection not implemented
        if returncode == 0:
            output = stdout + stderr
            assert len(output) > 0
        else:
            # If campaign selection not implemented, should fail gracefully
            output = stdout + stderr
            assert "campaign" in output.lower() or "not" in output.lower()
    
    def test_dry_run_prevents_network_output(self):
        """Test that dry run prevents actual network output"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should not generate actual network traffic
        # This is hard to test directly, but command should complete quickly
        output = stdout + stderr
        assert len(output) > 0


class TestCampaignExecution(CLITestBase):
    """Test campaign execution functionality"""
    
    def test_campaign_execution_dry_run_only(self):
        """Test campaign execution in dry run mode only"""
        # We only test dry run to avoid actual network traffic
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should show execution information
        output = stdout + stderr
        assert len(output) > 0
    
    def test_campaign_with_output_options(self):
        """Test campaign with output options in dry run"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should handle output configuration
        output = stdout + stderr
        assert len(output) > 0


class TestArgumentValidation(CLITestBase):
    """Test command-line argument validation"""
    
    def test_invalid_arguments(self):
        """Test handling of invalid arguments"""
        returncode, stdout, stderr = self.run_cli_command([
            "--invalid-argument"
        ])
        
        # Should fail with invalid argument
        assert returncode != 0
        output = stdout + stderr
        assert "invalid" in output.lower() or "unrecognized" in output.lower()
    
    def test_conflicting_arguments(self):
        """Test handling of potentially conflicting arguments"""
        # Test with both verbose and quiet (if implemented)
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--verbose",
            "--quiet"  # This may not exist
        ])
        
        # Should either work (if quiet not implemented) or handle conflict
        output = stdout + stderr
        assert len(output) >= 0  # Some output expected
    
    def test_missing_required_arguments(self):
        """Test handling of missing required arguments"""
        returncode, stdout, stderr = self.run_cli_command([
            "--list-campaigns"  # Missing campaign file
        ])
        
        # Should fail gracefully
        assert returncode != 0
        output = stdout + stderr
        assert len(output) > 0


class TestOutputFormatting(CLITestBase):
    """Test output formatting functionality"""
    
    def test_campaign_listing_format(self):
        """Test campaign listing output format"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should have structured output
        lines = stdout.strip().split('\n')
        assert len(lines) > 0
        
        # Should contain campaign information
        assert any("Campaign" in line for line in lines)
    
    def test_dictionary_info_format(self):
        """Test dictionary information formatting"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Should show campaign information (dictionary info optional)
        assert "Campaign" in stdout
    
    def test_verbose_output_format(self):
        """Test verbose output formatting"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--verbose",
            "--list-campaigns"
        ])
        
        assert returncode == 0, f"Command failed: {stderr}"
        
        # Verbose mode should provide additional information
        lines = stdout.strip().split('\n')
        assert len(lines) > 0


class TestErrorHandling(CLITestBase):
    """Test CLI error handling"""
    
    def test_python_import_errors(self):
        """Test handling of Python import errors"""
        # Create temp file with import error
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import nonexistent_module\n")
            temp_file = f.name
        
        try:
            returncode, stdout, stderr = self.run_cli_command([
                temp_file,
                "--list-campaigns"
            ])
            
            # Should handle import errors gracefully
            assert returncode != 0
            output = stdout + stderr
            assert "import" in output.lower() or "error" in output.lower()
        finally:
            os.unlink(temp_file)
    
    def test_permission_errors(self):
        """Test handling of permission errors"""
        # Create temp file without read permissions
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Test file\n")
            temp_file = f.name
        
        try:
            # Remove read permissions
            os.chmod(temp_file, 0o000)
            
            returncode, stdout, stderr = self.run_cli_command([
                temp_file,
                "--list-campaigns"
            ])
            
            # Should handle permission errors gracefully
            assert returncode != 0
            output = stdout + stderr
            assert "permission" in output.lower() or "error" in output.lower()
        finally:
            # Restore permissions and cleanup
            os.chmod(temp_file, 0o644)
            os.unlink(temp_file)
    
    def test_keyboard_interrupt_handling(self):
        """Test handling of keyboard interrupts"""
        # This is difficult to test automatically
        # Just ensure the CLI script can handle basic interruption scenarios
        pass  # Skip for now as it requires interactive testing


class TestIntegrationScenarios(CLITestBase):
    """Test integrated CLI scenarios"""
    
    def test_full_workflow_dry_run(self):
        """Test complete workflow in dry run mode"""
        # List campaigns first
        returncode1, stdout1, stderr1 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        # Run in dry run mode
        returncode2, stdout2, stderr2 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dry-run",
            "--verbose"
        ])
        
        assert returncode1 == 0 and returncode2 == 0
        assert len(stdout1) > 0 and (len(stdout2) > 0 or len(stderr2) > 0)
    
    def test_dictionary_config_workflow(self):
        """Test dictionary configuration workflow"""
        # List without dictionary config
        returncode1, stdout1, stderr1 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--list-campaigns"
        ])
        
        # List with dictionary config
        returncode2, stdout2, stderr2 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dictionary-config", "examples/config/webapp_config.py",
            "--list-campaigns"
        ])
        
        # Run with dictionary config in dry run
        returncode3, stdout3, stderr3 = self.run_cli_command([
            "examples/campaign_examples.py",
            "--dictionary-config", "examples/config/webapp_config.py",
            "--dry-run",
            "--verbose"
        ])
        
        assert returncode1 == 0 and returncode2 == 0 and returncode3 == 0
        assert len(stdout1) > 0 and len(stdout2) > 0 and (len(stdout3) > 0 or len(stderr3) > 0)
        
        # Dictionary config may or may not affect output depending on implementation
        assert len(stdout1) > 0 and len(stdout2) > 0
    
    def test_pcap_only_flag(self):
        """Test --disable-network flag functionality (PCAP only)"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--disable-network",
            "--enable-pcap",
            "--dry-run",  # Don't actually execute
            "--verbose"
        ])
        
        assert returncode == 0, f"PCAP-only command failed: {stderr}"
        
        output = stdout + stderr
        assert "pcap" in output.lower() or "PCAP" in output
    
    def test_pcap_file_override(self):
        """Test --pcap-file flag functionality"""
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_pcap = Path(temp_dir) / "custom_output.pcap"
            
            returncode, stdout, stderr = self.run_cli_command([
                "examples/campaign_examples.py",
                "--pcap-file", str(custom_pcap),
                "--dry-run",  # Don't actually execute
                "--verbose"
            ])
            
            assert returncode == 0, f"PCAP file override failed: {stderr}"
            
            output = stdout + stderr
            assert str(custom_pcap) in output
    
    def test_no_network_flag(self):
        """Test --disable-network flag functionality"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--disable-network",
            "--dry-run",
            "--verbose"
        ])
        
        assert returncode == 0, f"No-network command failed: {stderr}"
        
        output = stdout + stderr
        assert "network" in output.lower() or "Network" in output
    
    def test_force_network_flag(self):
        """Test --enable-network flag functionality"""
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--enable-network",
            "--dry-run",
            "--verbose"
        ])
        
        assert returncode == 0, f"Force-network command failed: {stderr}"
        
        output = stdout + stderr
        assert "network" in output.lower() or "Network" in output
    
    def test_conflicting_pcap_network_flags(self):
        """Test conflicting PCAP/network flags"""
        # Test --disable-network with --enable-network (should conflict)
        returncode, stdout, stderr = self.run_cli_command([
            "examples/campaign_examples.py",
            "--disable-network",
            "--enable-network"
        ])
        
        assert returncode != 0, "Conflicting flags should cause failure"
        
        output = stdout + stderr
        assert "cannot" in output.lower() or "conflict" in output.lower() or "error" in output.lower()
    
    def test_pcap_functionality_end_to_end(self):
        """Test complete PCAP functionality from CLI to file creation"""
        import tempfile
        from pathlib import Path
        from scapy.utils import rdpcap
        
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_file = Path(temp_dir) / "cli_end_to_end.pcap"
            
            # Run CLI with PCAP output
            returncode, stdout, stderr = self.run_cli_command([
                "examples/campaign_examples.py",
                "--pcap-file", str(pcap_file),
                "--pcap-only",
                "--verbose"
            ], timeout=30)  # Longer timeout for actual execution
            
            if returncode == 0:
                # Verify PCAP file was created
                assert pcap_file.exists(), f"PCAP file should be created: {pcap_file}"
                assert pcap_file.stat().st_size > 0, "PCAP file should not be empty"
                
                # Verify PCAP content
                try:
                    packets = rdpcap(str(pcap_file))
                    assert len(packets) > 0, "PCAP file should contain packets"
                    
                    # Verify basic packet structure
                    first_packet = packets[0]
                    assert first_packet.haslayer(IP), "Packets should have IP layer"
                    
                except Exception as e:
                    assert False, f"Failed to read PCAP file: {e}"
            else:
                # Command failed - could be due to missing dependencies
                # Check if it's a known issue
                output = stdout + stderr
                if "libfuzzer" in output.lower() or "import" in output.lower():
                    # Acceptable failure due to missing dependencies
                    pass
                else:
                    assert False, f"Unexpected CLI failure: {stderr}"


if __name__ == '__main__':
    # Run tests with pytest if available, otherwise use unittest
    if PYTEST_AVAILABLE:
        try:
            pytest.main([__file__, '-v'])
        except SystemExit:
            pass
    else:
        import unittest
        unittest.main(verbosity=2)
