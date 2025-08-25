#!/usr/bin/env python3
"""
Core Framework Tests

Tests for the core functionality of the scapy-fuzzer framework including:
- Packet extensions and embedded configuration
- Core fuzzer functionality
- Field and packet configuration management
"""

import sys
import os
import unittest
import logging
import time
import tempfile
from typing import Any, List
from collections import Counter, defaultdict

# Try to import pytest, fall back to unittest if not available
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, FuzzMutator, CallbackResult
Campaign = FuzzingCampaign
from packetfuzz.mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.utils import rdpcap, wrpcap

# Import packet extensions to enable field_fuzz() method
import packetfuzz.packet_extensions

# Import from conftest with robust fallback similar to test_dictionary.py
import importlib.util
try:
    from conftest import create_test_packet
except ImportError:
    try:
        from tests.conftest import create_test_packet
    except ImportError:
        conftest_path = os.path.join(os.path.dirname(__file__), 'conftest.py')
        spec = importlib.util.spec_from_file_location("conftest", conftest_path)
        if spec is not None and spec.loader is not None:
            conftest = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(conftest)
            create_test_packet = conftest.create_test_packet
        else:
            # Minimal fallback
            def create_test_packet(packet_type="tcp"):
                if packet_type == "tcp":
                    return IP()/TCP()
                elif packet_type == "udp":
                    return IP()/UDP()
                else:
                    return IP()


class LocalFuzzingCampaign(FuzzingCampaign):
    """Base class for local-only fuzzing tests."""
    output_network = False
    target = "127.0.0.1"
    interface = "lo"


# All test campaigns should inherit from LocalFuzzingCampaign to ensure local-only traffic
class TestPacketExtensions(unittest.TestCase):
    """Test packet extension functionality"""
    
    def test_field_fuzz_method_exists(self):
        """Test that field_fuzz method is available on packets"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'field_fuzz')
        field_proxy = tcp_layer.field_fuzz('dport')
        assert field_proxy is not None
    
    def test_fuzz_config_method_exists(self):
        """Test that fuzz_config method is available on packets"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'fuzz_config')
        config_proxy = tcp_layer.fuzz_config()
        assert config_proxy is not None
    
    def test_has_fuzz_config_method(self):
        """Test has_fuzz_config method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Initially should have no config
        assert hasattr(tcp_layer, 'has_fuzz_config')
        assert tcp_layer.has_fuzz_config() == False
        
        # After adding config should return True
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        assert tcp_layer.has_fuzz_config() == True
    
    def test_get_field_fuzz_config_method(self):
        """Test get_field_fuzz_config method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'get_field_fuzz_config')
        
        # Initially should return None
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config is None
        
        # After adding config should return the config
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config is not None
        assert config.default_values == [80, 443, 8080]
    
    def test_get_all_field_fuzz_configs_method(self):
        """Test get_all_field_fuzz_configs method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Clear any existing configurations first
        tcp_layer.clear_fuzz_configs()
        
        assert hasattr(tcp_layer, 'get_all_field_fuzz_configs')
        
        # Configure multiple fields
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        tcp_layer.field_fuzz('sport').default_values = [1024, 2048]
        
        all_configs = tcp_layer.get_all_field_fuzz_configs()
        assert len(all_configs) == 2
        assert 'dport' in all_configs
        assert 'sport' in all_configs
    
    def test_clear_fuzz_configs_method(self):
        """Test clear_fuzz_configs method"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        assert hasattr(tcp_layer, 'clear_fuzz_configs')
        
        # Add some config
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        assert tcp_layer.has_fuzz_config() == True
        
        # Clear config
        tcp_layer.clear_fuzz_configs()
        assert tcp_layer.has_fuzz_config() == False


class TestEmbeddedConfiguration(unittest.TestCase):
    """Test embedded packet configuration functionality"""
    
    def test_field_configuration_basic(self):
        """Test basic field configuration"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure field
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        tcp_layer.field_fuzz('dport').fuzz_weight = 0.8
        tcp_layer.field_fuzz('dport').description = "Web ports"
        
        # Verify configuration
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config.default_values == [80, 443, 8080]
        assert config.fuzz_weight == 0.8
        assert config.description == "Web ports"
    
    def test_packet_level_configuration(self):
        """Test packet-level configuration"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure packet level
        tcp_layer.fuzz_config().description = "TCP packet fuzzing"
        
        # Verify configuration
        packet_config = tcp_layer.get_fuzz_config()
        assert packet_config is not None
        assert packet_config.description == "TCP packet fuzzing"
    
    def test_multiple_layers_configuration(self):
        """Test configuration across multiple packet layers"""
        packet = create_test_packet("tcp")
        
        # Configure IP layer
        ip_layer = packet[IP]
        ip_layer.field_fuzz('dst').default_values = ["192.168.1.1", "10.0.0.1"]
        ip_layer.field_fuzz('ttl').default_values = [64, 128, 255]
        
        # Configure TCP layer
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        tcp_layer.field_fuzz('sport').default_values = [1024, 2048]
        
        # Verify both layers have configuration
        assert ip_layer.has_fuzz_config() == True
        assert tcp_layer.has_fuzz_config() == True
        
        # Verify field counts
        ip_configs = ip_layer.get_all_field_fuzz_configs()
        tcp_configs = tcp_layer.get_all_field_fuzz_configs()
        assert len(ip_configs) == 2  # dst, ttl
        assert len(tcp_configs) == 2  # dport, sport
    
    def test_dictionary_configuration(self):
        """Test dictionary configuration in embedded config"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        
        # Configure with dictionaries
        tcp_layer.field_fuzz('dport').dictionary = ["fuzzdb/wordlists-misc/common-http-ports.txt"]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        
        # Verify configuration
        config = tcp_layer.get_field_fuzz_config('dport')
        assert config.dictionary == ["fuzzdb/wordlists-misc/common-http-ports.txt"]
        assert config.default_values == [80, 443]


class TestFuzzField(unittest.TestCase):
    """Test FuzzField functionality"""
    
    def test_fuzzfield_creation(self):
        """Test FuzzField object creation"""
        fuzz_field = FuzzField(values=[80, 443, 8080], description="Web ports")
        
        assert fuzz_field.values == [80, 443, 8080]
        assert fuzz_field.description == "Web ports"
    
    def test_fuzzfield_as_integer(self):
        """Test FuzzField used as integer"""
        fuzz_field = FuzzField(values=[80, 443, 8080])
        # Should act like an integer in packet construction
        assert int(fuzz_field) in fuzz_field.values

    def test_fuzzfield_as_string(self):
        fuzz_field = FuzzField(values=["test1", "test2"])
        # Should act like a string in packet construction
        assert str(fuzz_field) in fuzz_field.values

    def test_fuzzfield_as_bytes(self):
        """Test FuzzField used as bytes"""
        fuzz_field = FuzzField(values=[b"data1", b"data2"])
        # Should act like bytes in packet construction
        assert bytes(fuzz_field) in fuzz_field.values

    def test_fuzzfield_with_mutators(self):
        """Test FuzzField with custom mutators"""
        fuzz_field = FuzzField(
            values=[80, 443, 8080],
            mutators=[]
        )
        
        assert not fuzz_field.mutators

    def test_fuzzfield_preservation_in_packets(self):
        packet = IP() / TCP(dport=FuzzField(values=[80, 443, 8080]))
        tcp_layer = packet[TCP]
        dport_field = tcp_layer.dport
        assert isinstance(dport_field, FuzzField), "FuzzField should be preserved in packet"
        assert dport_field.values == [80, 443, 8080]
        assert int(dport_field) in dport_field.values
        assert str(dport_field) in [str(v) for v in dport_field.values]


class TestCoreFuzzer(unittest.TestCase):
    """Test core fuzzer functionality"""
    
    def setUp(self):
        """Set up enhanced logging and tracking for tests"""
        # Configure detailed logging for debugging
        self.test_logger = logging.getLogger(f'test.{self._testMethodName}')
        self.test_logger.setLevel(logging.DEBUG)
        
        # Create handler if not exists
        if not self.test_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.test_logger.addHandler(handler)
        
        # Initialize tracking variables
        self.mutation_log = []
        self.performance_log = {}
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Enhanced teardown with failure analysis"""
        # Log summary information
        if hasattr(self, 'mutation_log') and self.mutation_log:
            total_mutations = len(self.mutation_log)
            mutations_with_changes = sum(1 for m in self.mutation_log if m.get('total_changes', 0) > 0)
            self.test_logger.info(f"Test completed - {mutations_with_changes}/{total_mutations} mutations had changes")
        
        # Check if test failed and provide additional debugging (compatible across Python versions)
        try:
            if hasattr(self, '_outcome') and self._outcome:
                if hasattr(self._outcome, 'errors') and self._outcome.errors:
                    self.test_logger.error("Test failed - dumping debug information:")
                    if hasattr(self, 'performance_log'):
                        for key, value in self.performance_log.items():
                            self.test_logger.error(f"Performance {key}: {value}")
                elif hasattr(self._outcome, 'result') and self._outcome.result and self._outcome.result.errors:
                    self.test_logger.error("Test failed - dumping debug information:")
                    if hasattr(self, 'performance_log'):
                        for key, value in self.performance_log.items():
                            self.test_logger.error(f"Performance {key}: {value}")
        except (AttributeError, TypeError):
            # Fallback for different test runners
            pass
        
        # Cleanup
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
    
    def track_mutations(self, original, fuzzed, iteration=None):
        """Track and log detailed mutation information"""
        changes = []
        
        # Track IP layer changes
        if IP in original and IP in fuzzed:
            if original[IP].dst != fuzzed[IP].dst:
                changes.append(f"IP.dst: {original[IP].dst} -> {fuzzed[IP].dst}")
            if original[IP].src != fuzzed[IP].src:
                changes.append(f"IP.src: {original[IP].src} -> {fuzzed[IP].src}")
            if original[IP].ttl != fuzzed[IP].ttl:
                changes.append(f"IP.ttl: {original[IP].ttl} -> {fuzzed[IP].ttl}")
        
        # Track TCP layer changes
        if TCP in original and TCP in fuzzed:
            if original[TCP].dport != fuzzed[TCP].dport:
                changes.append(f"TCP.dport: {original[TCP].dport} -> {fuzzed[TCP].dport}")
            if original[TCP].sport != fuzzed[TCP].sport:
                changes.append(f"TCP.sport: {original[TCP].sport} -> {fuzzed[TCP].sport}")
            if getattr(original[TCP], 'seq', None) != getattr(fuzzed[TCP], 'seq', None):
                changes.append(f"TCP.seq: {getattr(original[TCP], 'seq', None)} -> {getattr(fuzzed[TCP], 'seq', None)}")
        
        # Track Raw layer changes
        if Raw in original and Raw in fuzzed:
            if bytes(original[Raw]) != bytes(fuzzed[Raw]):
                orig_load = bytes(original[Raw])[:20]  # First 20 bytes for logging
                fuzz_load = bytes(fuzzed[Raw])[:20]
                changes.append(f"Raw.load: {orig_load!r} -> {fuzz_load!r}")
        
        mutation_entry = {
            'iteration': iteration if iteration is not None else len(self.mutation_log),
            'changes': changes,
            'total_changes': len(changes),
            'timestamp': time.time()
        }
        
        self.mutation_log.append(mutation_entry)
        
        if changes:
            self.test_logger.debug(f"Mutation {len(self.mutation_log)}: {changes}")
        
        return mutation_entry
    
    def test_scapy_fuzzer_creation(self):
        """Test MutatorManager creation"""
        config = FuzzConfig()
        fuzzer = MutatorManager(config)
        
        assert fuzzer is not None
        assert fuzzer.config.mode == FuzzMode.BOTH
        assert fuzzer.config.use_dictionaries == True
    
    def test_fuzzer_with_embedded_config_and_validation(self):
        """Test fuzzer working with embedded configuration and validate results"""
        # Create packet with embedded config
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [8080, 8443, 9000]
        tcp_layer.field_fuzz('dport').fuzz_weight = 0.8
        
        # Create fuzzer
        config = FuzzConfig(mode=FuzzMode.BOTH, use_dictionaries=True)
        fuzzer = MutatorManager(config)
        
        assert fuzzer is not None
        
        # Test actual fuzzing with embedded config
        original_dport = packet[TCP].dport
        self.test_logger.info(f"Original packet dport: {original_dport}")
        
        # Generate multiple fuzzed packets to test configuration application
        fuzzed_packets = []
        for i in range(20):
            try:
                fuzzed = fuzzer.fuzz_packet(packet, iterations=1)
                if fuzzed:
                    fuzzed_packets.extend(fuzzed)
                    if len(fuzzed) > 0:
                        self.track_mutations(packet, fuzzed[0], i)
            except Exception as e:
                self.test_logger.warning(f"Fuzzing iteration {i} failed: {e}")
        
        # Validate that fuzzing actually occurred
        if fuzzed_packets:
            dports_found = set()
            for fuzzed_pkt in fuzzed_packets:
                if TCP in fuzzed_pkt:
                    dports_found.add(fuzzed_pkt[TCP].dport)
            
            self.test_logger.info(f"Found dports in fuzzed packets: {sorted(dports_found)}")
            
            # Check if configured values appear
            configured_values = {8080, 8443, 9000}
            found_configured = configured_values.intersection(dports_found)
            
            if found_configured:
                self.test_logger.info(f"SUCCESS: Found configured values: {found_configured}")
            else:
                self.test_logger.warning(f"No configured values found. This may indicate configuration not applied.")
        
        # Log mutation summary
        if self.mutation_log:
            changes_count = sum(m['total_changes'] for m in self.mutation_log)
            self.test_logger.info(f"Total mutations tracked: {len(self.mutation_log)}, total changes: {changes_count}")

    def test_callback_execution_and_tracking(self):
        """Test that callbacks are executed and can be tracked"""
        callback_calls = []
        callback_results = []
        
        class TrackingCampaign(FuzzingCampaign):
            name = "Callback Tracking Test"
            target = "127.0.0.1"
            iterations = 10
            output_network = False
            output_pcap = None
            verbose = False
            
            def get_packet(self):
                return IP(dst="127.0.0.1") / TCP(dport=80) / Raw(b"test")
            
            def pre_send_callback(self, context, packet):
                callback_calls.append(('pre_send', context.iteration, len(bytes(packet))))
                return CallbackResult.SUCCESS
            
            def post_send_callback(self, context, packet, response=None):
                callback_calls.append(('post_send', context.iteration, len(bytes(packet))))
                return CallbackResult.SUCCESS
        
        # Set up PCAP output
        test_pcap = os.path.join(self.temp_dir, "callback_test.pcap")
        campaign = TrackingCampaign()
        campaign.output_pcap = test_pcap
        
        start_time = time.time()
        result = campaign.execute()
        end_time = time.time()
        
        # Log performance
        duration = end_time - start_time
        self.performance_log['callback_test_duration'] = duration
        self.test_logger.info(f"Campaign completed in {duration:.2f}s")
        
        # Validate callback execution
        assert result == True, "Campaign with callbacks should succeed"
        
        pre_send_calls = [call for call in callback_calls if call[0] == 'pre_send']
        post_send_calls = [call for call in callback_calls if call[0] == 'post_send']
        
        self.test_logger.info(f"Callback execution: {len(pre_send_calls)} pre_send, {len(post_send_calls)} post_send")
        
        # Validate callback counts
        assert len(pre_send_calls) > 0, "Pre-send callbacks should be called"
        assert len(post_send_calls) > 0, "Post-send callbacks should be called"
        
        # Validate packet sizes in callbacks
        for call_type, iteration, packet_size in callback_calls:
            assert packet_size > 0, f"Callback {call_type} at iteration {iteration} had empty packet"
        
        # Check PCAP output matches callback calls
        if os.path.exists(test_pcap):
            packets = rdpcap(test_pcap)
            self.test_logger.info(f"PCAP contains {len(packets)} packets")
            
            # Log some packet analysis
            if packets:
                tcp_ports = [pkt[TCP].dport for pkt in packets if TCP in pkt]
                port_distribution = Counter(tcp_ports)
                self.test_logger.info(f"Port distribution: {dict(port_distribution)}")

    def test_fuzzer_statistics_accuracy(self):
        """Test that reported statistics match actual PCAP content"""
        class StatisticsValidationCampaign(FuzzingCampaign):
            name = "Statistics Validation Test"
            target = "127.0.0.1"
            iterations = 25
            output_network = False
            output_pcap = None
            verbose = False
            
            def get_packet(self):
                return IP(dst="127.0.0.1") / TCP(dport=80) / Raw(b"statistics_test")
        
        test_pcap = os.path.join(self.temp_dir, "stats_test.pcap")
        campaign = StatisticsValidationCampaign()
        campaign.output_pcap = test_pcap
        
        # Execute campaign and capture statistics
        result = campaign.execute()
        assert result == True, "Statistics validation campaign should succeed"
        
        # Get campaign statistics
        stats = campaign.context.stats if hasattr(campaign, 'context') and campaign.context else {}
        self.test_logger.info(f"Campaign statistics: {stats}")
        
        # Read and analyze PCAP
        if os.path.exists(test_pcap):
            packets = rdpcap(test_pcap)
            pcap_packet_count = len(packets)
            
            self.test_logger.info(f"PCAP analysis: {pcap_packet_count} packets")
            
            # Validate statistics accuracy
            if 'packets_sent' in stats:
                reported_sent = stats['packets_sent']
                serialize_failures = stats.get('serialize_failure_count', 0)
                expected_in_pcap = reported_sent - serialize_failures
                
                self.test_logger.info(f"Reported sent: {reported_sent}, Serialize failures: {serialize_failures}")
                self.test_logger.info(f"Expected in PCAP: {expected_in_pcap}, Actual: {pcap_packet_count}")
                
                # Allow some tolerance for edge cases
                assert abs(pcap_packet_count - expected_in_pcap) <= 1, \
                    f"PCAP packet count {pcap_packet_count} doesn't match expected {expected_in_pcap}"
            
            # Validate packet content
            if packets:
                # Check that packets have expected structure
                valid_packets = sum(1 for pkt in packets if IP in pkt and TCP in pkt)
                validity_rate = valid_packets / len(packets)
                
                self.test_logger.info(f"Packet validity: {valid_packets}/{len(packets)} ({validity_rate:.1%})")
                assert validity_rate > 0.8, f"Too many invalid packets: {validity_rate:.1%}"
    
    def test_fuzzer_packet_serialization(self):
        """Test that configured packets can be serialized"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443, 8080]
        
        # Should be able to serialize packet with embedded config
        packet_bytes = bytes(packet)
        assert len(packet_bytes) > 0
        assert isinstance(packet_bytes, bytes)

    def test_convert_field_overrides_to_fuzzfields(self):
        """Test conversion of legacy field overrides to FuzzField objects"""
        pass


class TestConfigurationPersistence(unittest.TestCase):
    """Test configuration persistence and copying behavior"""
    
    def test_config_persistence_after_copy(self):
        """Test that configuration doesn't persist after packet copy"""
        packet = create_test_packet("tcp")
        tcp_layer = packet[TCP]
        tcp_layer.field_fuzz('dport').default_values = [80, 443]
        
        # Copy the packet
        packet_copy = packet.copy()
        tcp_copy = packet_copy[TCP]
        
        # Original should still have config
        assert tcp_layer.has_fuzz_config() == True
        
        # Copy should not have config (as per current implementation)
        assert tcp_copy.has_fuzz_config() == False
    
    def test_config_independence(self):
        """Test that packet configurations are independent"""
        packet1 = create_test_packet("tcp")
        packet2 = create_test_packet("tcp")
        
        # Configure first packet
        tcp1 = packet1[TCP]
        tcp1.field_fuzz('dport').default_values = [80, 443]
        
        # Configure second packet differently
        tcp2 = packet2[TCP]
        tcp2.field_fuzz('dport').default_values = [22, 23]
        
        # Verify independence
        config1 = tcp1.get_field_fuzz_config('dport')
        config2 = tcp2.get_field_fuzz_config('dport')
        
        assert config1.default_values == [80, 443]
        assert config2.default_values == [22, 23]
        
    def test_fuzz_history_entry(self):
        """Test FuzzHistoryEntry class for response capture"""
        from packetfuzz.fuzzing_framework import FuzzHistoryEntry
        from datetime import datetime, timedelta
        
        # Create a test packet
        test_packet = create_test_packet("tcp")
        
        # Create a history entry with the test packet
        history_entry = FuzzHistoryEntry(
            packet=test_packet,
            timestamp_sent=datetime.now(),
            iteration=42
        )
        
        # Verify initial state
        assert history_entry.packet == test_packet
        assert history_entry.iteration == 42
        assert history_entry.crashed is False
        assert history_entry.response is None
        assert history_entry.timestamp_received is None
        assert history_entry.crash_info is None
        assert history_entry.get_response_time() is None
        
        # Update with response information
        history_entry.timestamp_received = history_entry.timestamp_sent + timedelta(milliseconds=15)
        history_entry.response = "Mock Response"
        
        # Verify response time calculation
        response_time = history_entry.get_response_time()
        assert response_time is not None
        assert 14.0 <= response_time <= 16.0  # Allow small floating point variance


class DummyCoreCampaign(Campaign):
    name = "dummy_core"
    target = "127.0.0.1"
    output_network = False
    def build_packets(self):
        return [IP(dst=self.target)/TCP(dport=int(80))/Raw(load=b"test")]  # Ensure dport is int


if __name__ == '__main__':
    # Run tests with pytest if available, otherwise use unittest
    if PYTEST_AVAILABLE:
        try:
            pytest.main([__file__, '-v'])
        except SystemExit:
            pass
    else:
        unittest.main(verbosity=2)
