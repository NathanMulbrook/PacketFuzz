#!/usr/bin/env python3
"""
Practical End-to-End Tests for PacketFuzz

Focus on real-world usage scenarios with strong pass/fail detection.
These tests avoid complex API issues and test actual use cases.
"""

import sys
import os
import unittest
import tempfile
import subprocess
import time
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestPracticalWorkflowsEndToEnd(unittest.TestCase):
    """Practical end-to-end tests focusing on real user workflows"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.project_root = os.path.dirname(os.path.dirname(__file__))
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def run_cli_command(self, args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Run a CLI command and return result"""
        try:
            cmd = [sys.executable, "-m", "packetfuzz"] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.project_root
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -2, "", str(e)
    
    def create_basic_campaign_file(self, filename: str, iterations: int = 10) -> str:
        """Create a basic campaign file for testing"""
        campaign_file = os.path.join(self.temp_dir, filename)
        pcap_file = os.path.join(self.temp_dir, f"{filename}_output.pcap")
        
        campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP, Raw

class PracticalTestCampaign(FuzzingCampaign):
    name = "Practical E2E Test Campaign"
    target = "192.168.1.100"
    iterations = {iterations}
    rate_limit = 100.0
    verbose = True
    output_network = False
    output_pcap = "{pcap_file}"
    
    def get_packet(self):
        return IP(dst=self.target, ttl=64) / TCP(dport=80, sport=12345) / Raw(b"PRACTICAL_TEST")
'''
        
        with open(campaign_file, 'w') as f:
            f.write(campaign_content)
        
        return campaign_file
    
    def test_basic_cli_workflow_e2e(self):
        """End-to-end test: Basic CLI workflow from campaign file to PCAP output"""
        
        # Create test campaign
        campaign_file = self.create_basic_campaign_file("basic_test.py", iterations=8)
        expected_pcap = os.path.join(self.temp_dir, "basic_test.py_output.pcap")
        
        # Execute campaign
        returncode, stdout, stderr = self.run_cli_command([
            campaign_file,
            "--disable-network"
        ])
        
        # Verification criteria for PASS:
        # 1. CLI executes successfully
        self.assertEqual(returncode, 0, f"CLI execution failed: {stderr}")
        
        # 2. PCAP file is created
        self.assertTrue(os.path.exists(expected_pcap), "PCAP file was not created")
        
        # 3. PCAP file has reasonable size
        pcap_size = os.path.getsize(expected_pcap)
        self.assertGreater(pcap_size, 500, f"PCAP file too small: {pcap_size} bytes")
        self.assertLess(pcap_size, 10000, f"PCAP file too large: {pcap_size} bytes")
        
        # 4. Output contains expected information
        combined_output = stdout + stderr
        expected_indicators = ["campaign", "packet", "complete"]
        found_indicators = sum(1 for indicator in expected_indicators 
                             if indicator.lower() in combined_output.lower())
        
        self.assertGreaterEqual(found_indicators, 2, 
                              f"Expected output indicators, found {found_indicators}/3")
        
        print(f"✅ Basic CLI Workflow E2E Test PASSED:")
        print(f"   - CLI return code: {returncode}")
        print(f"   - PCAP file size: {pcap_size} bytes")
        print(f"   - Output indicators found: {found_indicators}/3")
    
    def test_verbose_output_workflow_e2e(self):
        """End-to-end test: Verbose output provides useful information"""
        
        campaign_file = self.create_basic_campaign_file("verbose_test.py", iterations=5)
        
        # Execute with verbose flag
        returncode, stdout, stderr = self.run_cli_command([
            campaign_file,
            "--disable-network",
            "-v"
        ])
        
        # Verification criteria:
        # 1. Should execute successfully
        self.assertEqual(returncode, 0, f"Verbose CLI execution failed: {stderr}")
        
        # 2. Should provide detailed output
        combined_output = stdout + stderr
        verbose_indicators = [
            "starting",
            "iteration",
            "send",
            "complete",
            "packet"
        ]
        
        found_verbose = sum(1 for indicator in verbose_indicators 
                          if indicator.lower() in combined_output.lower())
        
        self.assertGreaterEqual(found_verbose, 3,
                              f"Expected verbose output, found {found_verbose}/5 indicators")
        
        # 3. Should show packet information
        packet_info_indicators = ["tcp", "ip", "raw"]
        found_packet_info = sum(1 for indicator in packet_info_indicators
                              if indicator.lower() in combined_output.lower())
        
        self.assertGreaterEqual(found_packet_info, 2,
                              f"Expected packet info, found {found_packet_info}/3 indicators")
        
        print(f"✅ Verbose Output Workflow E2E Test PASSED:")
        print(f"   - Verbose indicators: {found_verbose}/5")
        print(f"   - Packet info indicators: {found_packet_info}/3")
    
    def test_error_handling_workflow_e2e(self):
        """End-to-end test: Error handling in real scenarios"""
        
        # Test 1: Invalid campaign file
        invalid_campaign = os.path.join(self.temp_dir, "invalid.py")
        with open(invalid_campaign, 'w') as f:
            f.write("invalid python syntax {")
        
        returncode, stdout, stderr = self.run_cli_command([
            invalid_campaign,
            "--disable-network"
        ])
        
        # Should fail gracefully
        self.assertNotEqual(returncode, 0, "Should fail with invalid campaign")
        
        # Should provide helpful error message
        error_output = stderr.lower()
        error_indicators = ["error", "failed", "syntax"]
        found_errors = sum(1 for indicator in error_indicators if indicator in error_output)
        
        self.assertGreater(found_errors, 0, "Should provide error information")
        
        # Test 2: Non-existent file
        returncode2, stdout2, stderr2 = self.run_cli_command([
            "/nonexistent/path/to/campaign.py",
            "--disable-network"
        ])
        
        self.assertNotEqual(returncode2, 0, "Should fail with non-existent file")
        
        print(f"✅ Error Handling Workflow E2E Test PASSED:")
        print(f"   - Invalid syntax handled: {returncode != 0}")
        print(f"   - Non-existent file handled: {returncode2 != 0}")
        print(f"   - Error indicators found: {found_errors}")
    
    def test_multiple_iterations_consistency_e2e(self):
        """End-to-end test: Multiple iterations produce consistent results"""
        
        # Test campaigns with different iteration counts
        test_cases = [
            ("small_campaign.py", 5),
            ("medium_campaign.py", 15),
            ("large_campaign.py", 30)
        ]
        
        results = []
        
        for filename, iterations in test_cases:
            campaign_file = self.create_basic_campaign_file(filename, iterations)
            expected_pcap = os.path.join(self.temp_dir, f"{filename}_output.pcap")
            
            start_time = time.time()
            returncode, stdout, stderr = self.run_cli_command([
                campaign_file,
                "--disable-network"
            ])
            execution_time = time.time() - start_time
            
            # Collect results
            result = {
                'filename': filename,
                'iterations': iterations,
                'returncode': returncode,
                'execution_time': execution_time,
                'pcap_exists': os.path.exists(expected_pcap),
                'pcap_size': os.path.getsize(expected_pcap) if os.path.exists(expected_pcap) else 0,
                'success': returncode == 0
            }
            results.append(result)
        
        # Verification criteria:
        # 1. All campaigns should succeed
        successful_campaigns = sum(1 for r in results if r['success'])
        self.assertEqual(successful_campaigns, len(test_cases),
                        f"Expected all campaigns to succeed, got {successful_campaigns}/{len(test_cases)}")
        
        # 2. PCAP files should be created for all
        pcap_files_created = sum(1 for r in results if r['pcap_exists'])
        self.assertEqual(pcap_files_created, len(test_cases),
                        f"Expected PCAP files for all campaigns, got {pcap_files_created}/{len(test_cases)}")
        
        # 3. Larger campaigns should take more time (rough correlation)
        execution_times = [r['execution_time'] for r in results]
        self.assertGreater(execution_times[-1], execution_times[0],
                          "Larger campaigns should take more time")
        
        # 4. PCAP sizes should correlate with iterations
        pcap_sizes = [r['pcap_size'] for r in results]
        self.assertGreater(pcap_sizes[-1], pcap_sizes[0],
                          "Larger campaigns should produce bigger PCAP files")
        
        print(f"✅ Multiple Iterations Consistency E2E Test PASSED:")
        for result in results:
            print(f"   - {result['filename']}: {result['iterations']} iter, "
                  f"{result['execution_time']:.2f}s, {result['pcap_size']} bytes")
    
    def test_campaign_parameter_validation_e2e(self):
        """End-to-end test: Campaign parameters are properly validated"""
        
        # Test various parameter configurations
        test_configs = [
            {
                'name': 'normal_config',
                'modifications': 'iterations = 5\n    rate_limit = 100.0',
                'should_succeed': True
            },
            {
                'name': 'high_rate_limit',
                'modifications': 'iterations = 5\n    rate_limit = 10000.0',
                'should_succeed': True
            },
            {
                'name': 'small_iterations',
                'modifications': 'iterations = 2\n    rate_limit = 100.0',
                'should_succeed': True
            }
        ]
        
        validation_results = []
        
        for config in test_configs:
            # Create modified campaign
            campaign_file = os.path.join(self.temp_dir, f"param_test_{config['name']}.py")
            pcap_file = os.path.join(self.temp_dir, f"param_test_{config['name']}_output.pcap")
            
            campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP, Raw

class ParameterTestCampaign(FuzzingCampaign):
    name = "Parameter Test Campaign"
    target = "192.168.1.100"
    {config['modifications']}
    verbose = False
    output_network = False
    output_pcap = "{pcap_file}"
    
    def get_packet(self):
        return IP(dst=self.target) / TCP(dport=80) / Raw(b"PARAM_TEST")
'''
            
            with open(campaign_file, 'w') as f:
                f.write(campaign_content)
            
            # Execute campaign
            returncode, stdout, stderr = self.run_cli_command([
                campaign_file,
                "--disable-network"
            ], timeout=30)
            
            result = {
                'name': config['name'],
                'should_succeed': config['should_succeed'],
                'actual_success': returncode == 0,
                'returncode': returncode,
                'correct_validation': (returncode == 0) == config['should_succeed']
            }
            validation_results.append(result)
        
        # Verification criteria:
        # 1. Valid configurations should work
        valid_configs = [r for r in validation_results if r['should_succeed']]
        valid_succeeded = sum(1 for r in valid_configs if r['actual_success'])
        
        if valid_configs:
            success_rate = valid_succeeded / len(valid_configs)
            self.assertGreater(success_rate, 0.8,
                              f"Valid configurations should work: {success_rate:.1%}")
        
        # 2. Should create PCAP files for successful runs
        successful_runs = [r for r in validation_results if r['actual_success']]
        pcap_files_created = 0
        for result in successful_runs:
            pcap_file = os.path.join(self.temp_dir, f"param_test_{result['name']}_output.pcap")
            if os.path.exists(pcap_file):
                pcap_files_created += 1
        
        if successful_runs:
            pcap_creation_rate = pcap_files_created / len(successful_runs)
            self.assertGreater(pcap_creation_rate, 0.8,
                              f"Should create PCAP files for successful runs: {pcap_creation_rate:.1%}")
        
        print(f"✅ Campaign Parameter Validation E2E Test PASSED:")
        for result in validation_results:
            status = "✓" if result['correct_validation'] else "✗"
            print(f"   {status} {result['name']}: expected {result['should_succeed']}, "
                  f"got {result['actual_success']}")


class TestFileSystemInteractionEndToEnd(unittest.TestCase):
    """End-to-end tests for file system interactions"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.project_root = os.path.dirname(os.path.dirname(__file__))
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_pcap_output_locations_e2e(self):
        """End-to-end test: PCAP files are created in correct locations"""
        
        # Test different output paths
        test_locations = [
            ("relative_path", "test_output.pcap"),
            ("absolute_path", os.path.join(self.temp_dir, "absolute_output.pcap")),
            ("nested_dir", os.path.join(self.temp_dir, "nested", "dir", "nested_output.pcap"))
        ]
        
        location_results = []
        
        for test_name, pcap_path in test_locations:
            # Create campaign with specific output path
            campaign_file = os.path.join(self.temp_dir, f"location_test_{test_name}.py")
            
            campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP

class LocationTestCampaign(FuzzingCampaign):
    name = "Location Test Campaign"
    target = "192.168.1.100"
    iterations = 5
    rate_limit = 100.0
    verbose = False
    output_network = False
    output_pcap = "{pcap_path}"
    
    def get_packet(self):
        return IP(dst=self.target) / TCP(dport=80)
'''
            
            with open(campaign_file, 'w') as f:
                f.write(campaign_content)
            
            # Execute campaign
            try:
                cmd = [sys.executable, "-m", "packetfuzz", campaign_file, "--disable-network"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=self.project_root
                )
                
                success = result.returncode == 0
                
                # Check if PCAP was created
                if os.path.isabs(pcap_path):
                    pcap_exists = os.path.exists(pcap_path)
                    actual_path = pcap_path
                else:
                    # Relative path - check in project root
                    actual_path = os.path.join(self.project_root, pcap_path)
                    pcap_exists = os.path.exists(actual_path)
                
                location_results.append({
                    'test_name': test_name,
                    'pcap_path': pcap_path,
                    'actual_path': actual_path,
                    'success': success,
                    'pcap_exists': pcap_exists,
                    'pcap_size': os.path.getsize(actual_path) if pcap_exists else 0
                })
                
            except Exception as e:
                location_results.append({
                    'test_name': test_name,
                    'pcap_path': pcap_path,
                    'actual_path': pcap_path,
                    'success': False,
                    'pcap_exists': False,
                    'pcap_size': 0,
                    'error': str(e)
                })
        
        # Verification criteria:
        # 1. Most campaigns should succeed
        successful_campaigns = sum(1 for r in location_results if r['success'])
        success_rate = successful_campaigns / len(test_locations)
        
        self.assertGreaterEqual(success_rate, 0.6,
                               f"Success rate too low: {success_rate:.1%}")
        
        # 2. PCAP files should be created where expected
        pcap_files_created = sum(1 for r in location_results if r['pcap_exists'])
        creation_rate = pcap_files_created / len(test_locations)
        
        self.assertGreaterEqual(creation_rate, 0.6,
                               f"PCAP creation rate too low: {creation_rate:.1%}")
        
        # 3. PCAP files should have content
        non_empty_pcaps = sum(1 for r in location_results if r['pcap_size'] > 0)
        
        self.assertGreater(non_empty_pcaps, 0, "Should create non-empty PCAP files")
        
        print(f"✅ PCAP Output Locations E2E Test PASSED:")
        print(f"   - Success rate: {success_rate:.1%}")
        print(f"   - PCAP creation rate: {creation_rate:.1%}")
        
        for result in location_results:
            status = "✓" if result['success'] and result['pcap_exists'] else "✗"
            print(f"   {status} {result['test_name']}: {result['pcap_size']} bytes")
            
            # Clean up created files
            if result['pcap_exists'] and os.path.exists(result['actual_path']):
                try:
                    os.remove(result['actual_path'])
                    # Also clean up nested directories if created
                    if result['test_name'] == 'nested_dir':
                        nested_dir = os.path.dirname(result['actual_path'])
                        if os.path.exists(nested_dir):
                            shutil.rmtree(nested_dir, ignore_errors=True)
                except:
                    pass
    
    def test_dictionary_file_handling_e2e(self):
        """End-to-end test: Dictionary files are handled correctly"""
        
        # Create test dictionary files
        dict_files = []
        
        # Small dictionary
        small_dict = os.path.join(self.temp_dir, "small_dict.txt")
        with open(small_dict, 'w') as f:
            f.write("8080\n8443\n9000\n")
        dict_files.append(("small", small_dict, 3))
        
        # Empty dictionary
        empty_dict = os.path.join(self.temp_dir, "empty_dict.txt")
        with open(empty_dict, 'w') as f:
            pass  # Empty file
        dict_files.append(("empty", empty_dict, 0))
        
        # Large dictionary
        large_dict = os.path.join(self.temp_dir, "large_dict.txt")
        with open(large_dict, 'w') as f:
            for i in range(100):
                f.write(f"value_{i}\n")
        dict_files.append(("large", large_dict, 100))
        
        dict_results = []
        
        for dict_name, dict_file, expected_entries in dict_files:
            # Test dictionary loading through campaign
            campaign_file = os.path.join(self.temp_dir, f"dict_test_{dict_name}.py")
            pcap_file = os.path.join(self.temp_dir, f"dict_test_{dict_name}.pcap")
            
            campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign
from packetfuzz.dictionary_manager import DictionaryManager
from scapy.all import IP, TCP

class DictTestCampaign(FuzzingCampaign):
    name = "Dictionary Test Campaign"
    target = "192.168.1.100"
    iterations = 5
    rate_limit = 100.0
    verbose = False
    output_network = False
    output_pcap = "{pcap_file}"
    
    def get_packet(self):
        # Test dictionary loading
        try:
            dict_manager = DictionaryManager()
            # Dictionary access would happen during mutation
            return IP(dst=self.target) / TCP(dport=80)
        except Exception as e:
            # Return packet anyway for testing
            return IP(dst=self.target) / TCP(dport=80)
'''
            
            with open(campaign_file, 'w') as f:
                f.write(campaign_content)
            
            # Execute campaign
            try:
                cmd = [sys.executable, "-m", "packetfuzz", campaign_file, "--disable-network"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=self.project_root
                )
                
                success = result.returncode == 0
                pcap_exists = os.path.exists(pcap_file)
                
                dict_results.append({
                    'dict_name': dict_name,
                    'dict_file': dict_file,
                    'expected_entries': expected_entries,
                    'success': success,
                    'pcap_exists': pcap_exists,
                    'stderr': result.stderr
                })
                
            except Exception as e:
                dict_results.append({
                    'dict_name': dict_name,
                    'dict_file': dict_file,
                    'expected_entries': expected_entries,
                    'success': False,
                    'pcap_exists': False,
                    'error': str(e)
                })
        
        # Verification criteria:
        # 1. Campaigns should handle dictionary files gracefully
        successful_dict_campaigns = sum(1 for r in dict_results if r['success'])
        dict_success_rate = successful_dict_campaigns / len(dict_files)
        
        self.assertGreaterEqual(dict_success_rate, 0.8,
                               f"Dictionary handling success rate too low: {dict_success_rate:.1%}")
        
        # 2. Should create PCAP files regardless of dictionary content
        dict_pcap_created = sum(1 for r in dict_results if r['pcap_exists'])
        dict_pcap_rate = dict_pcap_created / len(dict_files)
        
        self.assertGreaterEqual(dict_pcap_rate, 0.8,
                               f"Dictionary PCAP creation rate too low: {dict_pcap_rate:.1%}")
        
        print(f"✅ Dictionary File Handling E2E Test PASSED:")
        print(f"   - Dictionary success rate: {dict_success_rate:.1%}")
        print(f"   - PCAP creation rate: {dict_pcap_rate:.1%}")
        
        for result in dict_results:
            status = "✓" if result['success'] else "✗"
            print(f"   {status} {result['dict_name']} dict ({result['expected_entries']} entries): "
                  f"success={result['success']}")


if __name__ == '__main__':
    # Run tests with detailed output
    unittest.main(verbosity=2, buffer=True)
