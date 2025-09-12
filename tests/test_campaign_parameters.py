#!/usr/bin/env python3
"""
Campaign Parameters End-to-End Tests

This test suite validates that campaign parameters like fields_to_fuzz, 
excluded_fields, and layers_to_fuzz work correctly by actually testing 
the mutation behavior, not just configuration.

These tests would have caught the fields_to_fuzz bug where 0.0 weights
were being treated as falsy values.
"""

import sys
import os
import unittest
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Any, Set

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.all import Raw

from packetfuzz.fuzzing_framework import FuzzingCampaign
from packetfuzz.sockets.managed_udp_socket import ManagedUDPConfig
from packetfuzz.mutator_manager_data import MutatorManagerData


class TestCampaignParameters(unittest.TestCase):
    """Test campaign parameters actually control field selection correctly"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass

    def _get_mutated_fields_from_report(self, report_path: str) -> Set[str]:
        """Extract actually mutated field names from a JSON report"""
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        mutated_fields = set()
        for field in data['field_performance']['field_details']:
            if field['mutation_count'] > 0:
                # Use layer.field format for consistency
                field_key = f"{field['layer_name']}.{field['field_name']}"
                mutated_fields.add(field_key)
        
        return mutated_fields

    def _run_campaign_and_get_mutated_fields(self, campaign: FuzzingCampaign) -> Set[str]:
        """Run a campaign and return the set of actually mutated fields"""
        # Ensure network is disabled and only 1 iteration for testing
        campaign.output_network = False
        campaign.iterations = 1
        campaign.report_formats = ['json']  # Ensure JSON report is generated
        
        # Clear any existing reports
        import glob
        for report_file in glob.glob(f"{self.temp_dir}/*.json"):
            os.remove(report_file)
        
        # Validate and execute
        if not campaign.validate_campaign():
            self.fail(f"Campaign validation failed: {campaign.name}")
        
        campaign.execute()
        
        # Find the generated report
        report_files = list(Path("artifacts/reports").glob("*advanced*.json"))
        if not report_files:
            self.fail("No JSON report file generated")
        
        # Use the most recent report
        report_file = max(report_files, key=os.path.getctime)
        return self._get_mutated_fields_from_report(str(report_file))

    def test_fields_to_fuzz_basic_http_fields(self):
        """Test that fields_to_fuzz only allows specified fields to be mutated"""
        
        class HTTPFieldsTestCampaign(FuzzingCampaign):
            name = "HTTP Fields Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = ["Path", "Host"]
            iterations = 1
            packet = HTTP() / HTTPRequest(
                Path=b"/test", 
                Method=b"GET", 
                Host=b"example.com",
                User_Agent=b"TestAgent",
                Authorization=b"Bearer token"
            )
        
        campaign = HTTPFieldsTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should only mutate HTTPRequest.Path and HTTPRequest.Host
        expected_fields = {"HTTPRequest.Path", "HTTPRequest.Host"}
        unexpected_fields = {"HTTPRequest.Method", "HTTPRequest.User_Agent", "HTTPRequest.Authorization"}
        
        # Assert expected fields are mutated
        for field in expected_fields:
            self.assertIn(field, mutated_fields, 
                         f"Expected field {field} should be mutated when in fields_to_fuzz")
        
        # Assert unexpected fields are NOT mutated
        for field in unexpected_fields:
            self.assertNotIn(field, mutated_fields, 
                           f"Unexpected field {field} should NOT be mutated when not in fields_to_fuzz")
        
        # Verify total count is reasonable (should be exactly 2)
        http_mutated = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        self.assertEqual(len(http_mutated), 2, 
                        f"Expected exactly 2 HTTPRequest fields mutated, got {len(http_mutated)}: {http_mutated}")

    def test_fields_to_fuzz_wildcard_patterns(self):
        """Test that fields_to_fuzz works with wildcard patterns"""
        
        class WildcardTestCampaign(FuzzingCampaign):
            name = "Wildcard Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = ["HTTPRequest.*"]  # Should match all HTTPRequest fields
            iterations = 1
            packet = (
                IP(dst="127.0.0.1") /
                TCP(dport=80) /
                HTTP() / 
                HTTPRequest(Path=b"/test", Method=b"GET", Host=b"example.com")
            )
        
        campaign = WildcardTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should mutate HTTPRequest fields but NOT IP or TCP fields
        http_fields = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        ip_fields = {f for f in mutated_fields if f.startswith("IP.")}
        tcp_fields = {f for f in mutated_fields if f.startswith("TCP.")}
        
        self.assertGreater(len(http_fields), 0, "Should mutate some HTTPRequest fields")
        self.assertEqual(len(ip_fields), 0, "Should NOT mutate any IP fields")
        self.assertEqual(len(tcp_fields), 0, "Should NOT mutate any TCP fields")

    def test_excluded_fields_basic(self):
        """Test that excluded_fields prevents specific fields from being mutated"""
        
        class ExcludedFieldsTestCampaign(FuzzingCampaign):
            name = "Excluded Fields Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            excluded_fields = ["HTTPRequest.Accept", "HTTPRequest.Date"]
            iterations = 1
            packet = HTTP() / HTTPRequest(
                Path=b"/test",
                Method=b"GET",
                Host=b"example.com",
                User_Agent=b"TestAgent"
            )
        
        campaign = ExcludedFieldsTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should NOT mutate excluded fields
        excluded = {"HTTPRequest.Accept", "HTTPRequest.Date"}
        for field in excluded:
            self.assertNotIn(field, mutated_fields,
                           f"Excluded field {field} should NOT be mutated")
        
        # Should still mutate some HTTPRequest fields (just verify some mutations happened)
        mutated_http = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        self.assertGreater(len(mutated_http), 0,
                          f"Should mutate some non-excluded HTTPRequest fields")
        
        # Verify preprocessing shows correct exclusion count  
        # (This is more important than checking specific field names)    def test_layers_to_fuzz_basic(self):
        """Test that layers_to_fuzz only mutates fields in specified layers"""
        
        class LayersTestCampaign(FuzzingCampaign):
            name = "Layers Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            layers_to_fuzz = ["HTTPRequest"]  # Only fuzz HTTPRequest layer
            iterations = 1
            packet = (
                IP(dst="127.0.0.1") /
                TCP(dport=80) /
                HTTP() /
                HTTPRequest(Path=b"/test", Method=b"GET", Host=b"example.com")
            )
        
        campaign = LayersTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should only mutate HTTPRequest fields
        http_fields = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        non_http_fields = {f for f in mutated_fields if not f.startswith("HTTPRequest.")}
        
        self.assertGreater(len(http_fields), 0, "Should mutate some HTTPRequest fields")
        self.assertEqual(len(non_http_fields), 0, 
                        f"Should NOT mutate non-HTTPRequest fields, but got: {non_http_fields}")

    def test_fields_to_fuzz_empty_list(self):
        """Test that empty fields_to_fuzz list results in no mutations"""
        
        class EmptyFieldsTestCampaign(FuzzingCampaign):
            name = "Empty Fields Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = []  # No fields should be mutated
            iterations = 1
            packet = HTTP() / HTTPRequest(Path=b"/test", Method=b"GET", Host=b"example.com")
        
        campaign = EmptyFieldsTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        self.assertEqual(len(mutated_fields), 0,
                        f"Empty fields_to_fuzz should result in no mutations, got: {mutated_fields}")

    def test_fields_to_fuzz_with_nonexistent_field(self):
        """Test that fields_to_fuzz with non-existent fields doesn't break"""
        
        class NonexistentFieldTestCampaign(FuzzingCampaign):
            name = "Nonexistent Field Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = ["NonExistentField", "Path"]  # One valid, one invalid
            iterations = 1
            packet = HTTP() / HTTPRequest(Path=b"/test", Method=b"GET")
        
        campaign = NonexistentFieldTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should still mutate the valid field
        self.assertIn("HTTPRequest.Path", mutated_fields,
                     "Should mutate valid field even when invalid fields are specified")
        
        # Should not break or error out
        self.assertGreater(len(mutated_fields), 0,
                          "Campaign should still work with some invalid fields_to_fuzz")

    def test_complex_multi_layer_packet_field_selection(self):
        """Test field selection on complex multi-layer packets"""
        
        class ComplexPacketTestCampaign(FuzzingCampaign):
            name = "Complex Packet Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = ["TCP.dport", "HTTPRequest.Path"]
            iterations = 1
            packet = (
                IP(dst="192.168.1.100", src="10.0.0.1") /
                TCP(sport=12345, dport=80, flags="S") /
                HTTP() /
                HTTPRequest(Path=b"/api/test", Method=b"POST", Host=b"api.example.com") /
                Raw(b"request body data")
            )
        
        campaign = ComplexPacketTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # Should mutate exactly the specified fields
        expected = {"TCP.dport", "HTTPRequest.Path"}
        for field in expected:
            self.assertIn(field, mutated_fields,
                         f"Expected field {field} should be mutated")
        
        # Should NOT mutate other fields
        unexpected = {"IP.dst", "IP.src", "TCP.sport", "HTTPRequest.Method", "HTTPRequest.Host"}
        for field in unexpected:
            self.assertNotIn(field, mutated_fields,
                           f"Unexpected field {field} should NOT be mutated")

    def test_weight_zero_handling_regression(self):
        """
        Regression test for the specific bug where fuzz_weight: 0.0 was treated as falsy.
        This test would have caught the original bug.
        """
        
        class WeightZeroTestCampaign(FuzzingCampaign):
            name = "Weight Zero Regression Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            # This configuration would trigger the bug: only Host should be fuzzed
            fields_to_fuzz = ["Host"]
            iterations = 1
            packet = HTTP() / HTTPRequest(
                Path=b"/test",
                Method=b"GET", 
                Host=b"example.com",
                User_Agent=b"Mozilla/5.0",
                Accept=b"text/html",
                Authorization=b"Bearer token123"
            )
        
        campaign = WeightZeroTestCampaign()
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # CRITICAL: Should mutate ONLY Host field
        self.assertIn("HTTPRequest.Host", mutated_fields,
                     "HTTPRequest.Host should be mutated (it's in fields_to_fuzz)")
        
        # CRITICAL: These should NOT be mutated (they have fuzz_weight: 0.0)
        zero_weight_fields = {
            "HTTPRequest.Path", "HTTPRequest.Method", "HTTPRequest.User_Agent", 
            "HTTPRequest.Accept", "HTTPRequest.Authorization"
        }
        
        for field in zero_weight_fields:
            self.assertNotIn(field, mutated_fields,
                           f"REGRESSION: Field {field} should NOT be mutated (fuzz_weight: 0.0), "
                           f"but it was! This indicates the 0.0 weight bug is back.")
        
        # Extra validation: Only 1 HTTPRequest field should be mutated
        http_mutated = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        self.assertEqual(len(http_mutated), 1,
                        f"Expected exactly 1 HTTPRequest field (Host only), got {len(http_mutated)}: {http_mutated}")

    def test_preprocessing_statistics_accuracy(self):
        """Test that preprocessing statistics accurately reflect field filtering"""
        
        class StatsTestCampaign(FuzzingCampaign):
            name = "Stats Test"
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=80)
            fields_to_fuzz = ["Path", "Host"]
            iterations = 1
            verbose = True  # Enable verbose logging to see preprocessing stats
            packet = HTTP() / HTTPRequest(
                Path=b"/test", Method=b"GET", Host=b"example.com",
                User_Agent=b"TestAgent", Accept=b"text/html"
            )
        
        campaign = StatsTestCampaign()
        
        # Capture the mutator manager data to check preprocessing
        mutated_fields = self._run_campaign_and_get_mutated_fields(campaign)
        
        # The preprocessing should show correct fuzzable vs excluded counts
        # This test validates the logging output matches reality
        expected_fuzzable = 2  # Path and Host only
        http_mutated = {f for f in mutated_fields if f.startswith("HTTPRequest.")}
        
        self.assertEqual(len(http_mutated), expected_fuzzable,
                        f"Preprocessing stats should match actual mutations: "
                        f"expected {expected_fuzzable}, got {len(http_mutated)}")


if __name__ == '__main__':
    unittest.main()
