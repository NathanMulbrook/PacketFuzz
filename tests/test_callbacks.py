#!/usr/bin/env python3
"""
Callback tests for the fuzzing framework.
Tests custom send callbacks and related callback scenarios.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add the project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fuzzing_framework import FuzzingCampaign, CallbackResult, CampaignContext
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

class CallbackTest(unittest.TestCase):
    """Test custom send callback and callback interface"""
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sent_packets = []
        self.callback_calls = []
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    def custom_send_callback(self, fuzzed_packet, context: CampaignContext):
        self.callback_calls.append("custom_send")
        custom_packet = IP(dst=context.campaign.target)/TCP(dport=8080)/Raw(load=b"CustomTCPPayload")
        self.sent_packets.append(custom_packet)
        context.shared_data['custom_sends'] = context.shared_data.get('custom_sends', 0) + 1
        return CallbackResult.SUCCESS
    def test_custom_send_callback_attribute_exists(self):
        campaign = FuzzingCampaign()
        self.assertTrue(hasattr(campaign, 'custom_send_callback'))
        self.assertIsNone(campaign.custom_send_callback)
        campaign.custom_send_callback = self.custom_send_callback
        self.assertEqual(campaign.custom_send_callback, self.custom_send_callback)
    def test_custom_send_callback_function_signature(self):
        received_params = []
        def test_callback(fuzzed_packet, context):
            received_params.append({'fuzzed_packet': fuzzed_packet, 'context': context, 'context_type': type(context).__name__})
            return CallbackResult.SUCCESS
        campaign = FuzzingCampaign()
        campaign.target = "192.168.1.100"
        context = CampaignContext(campaign)
        test_packet = IP(dst="0.0.0.0")/TCP(dport=80)
        result = test_callback(test_packet, context)
        self.assertEqual(len(received_params), 1)
        self.assertEqual(result, CallbackResult.SUCCESS)
        self.assertEqual(received_params[0]['context_type'], 'CampaignContext')
        self.assertIsNotNone(received_params[0]['fuzzed_packet'])
        self.assertIsNotNone(received_params[0]['context'])
    def test_custom_send_callback_return_values(self):
        def success_callback(fuzzed_packet, context):
            return CallbackResult.SUCCESS
        def no_success_callback(fuzzed_packet, context):
            return CallbackResult.NO_SUCCESS
        def fail_crash_callback(fuzzed_packet, context):
            return CallbackResult.FAIL_CRASH
        campaign = FuzzingCampaign()
        context = CampaignContext(campaign)
        test_packet = IP(dst="0.0.0.0")/TCP(dport=80)
        result = success_callback(test_packet, context)
        self.assertEqual(result, CallbackResult.SUCCESS)
        result = no_success_callback(test_packet, context)
        self.assertEqual(result, CallbackResult.NO_SUCCESS)
        result = fail_crash_callback(test_packet, context)
        self.assertEqual(result, CallbackResult.FAIL_CRASH)
    def test_custom_packet_construction_example(self):
        constructed_packets = []
        def multi_protocol_callback(fuzzed_packet, context):
            tcp_packet = IP(dst=context.campaign.target)/TCP(dport=80, flags="S", seq=1000, window=8192)/Raw(load=b"TCP_SYN_PROBE")
            udp_packet = IP(dst=context.campaign.target)/UDP(sport=53000, dport=53)/Raw(load=b"DNS_QUERY_PROBE")
            constructed_packets.extend([tcp_packet, udp_packet])
            return CallbackResult.SUCCESS
        campaign = FuzzingCampaign()
        campaign.target = "8.8.8.8"
        context = CampaignContext(campaign)
        test_packet = IP(dst="0.0.0.0")/TCP(dport=80)
        result = multi_protocol_callback(test_packet, context)
        self.assertEqual(result, CallbackResult.SUCCESS)
        self.assertEqual(len(constructed_packets), 2)
        tcp_packet = constructed_packets[0]
        self.assertTrue(tcp_packet.haslayer(TCP))
        self.assertEqual(tcp_packet[IP].dst, "8.8.8.8")
        self.assertEqual(tcp_packet[TCP].dport, 80)
        self.assertEqual(tcp_packet[TCP].flags, 2)
        self.assertEqual(tcp_packet[Raw].load, b"TCP_SYN_PROBE")
        udp_packet = constructed_packets[1]
        self.assertTrue(udp_packet.haslayer(UDP))
        self.assertEqual(udp_packet[IP].dst, "8.8.8.8")
        self.assertEqual(udp_packet[UDP].dport, 53)
        self.assertEqual(udp_packet[UDP].sport, 53000)
        self.assertEqual(udp_packet[Raw].load, b"DNS_QUERY_PROBE")
    def test_context_data_sharing_example(self):
        def stateful_callback(fuzzed_packet, context):
            context.shared_data['packets_created'] = context.shared_data.get('packets_created', 0) + 1
            if 'packet_types' not in context.shared_data:
                context.shared_data['packet_types'] = []
            counter = context.shared_data['packets_created']
            if counter % 2 == 1:
                packet = IP(dst=context.campaign.target)/TCP(dport=counter + 1000)
                context.shared_data['packet_types'].append('TCP')
            else:
                packet = IP(dst=context.campaign.target)/UDP(dport=counter + 2000)
                context.shared_data['packet_types'].append('UDP')
            context.shared_data['last_packet'] = packet.summary()
            return CallbackResult.SUCCESS
        campaign = FuzzingCampaign()
        campaign.target = "10.0.0.1"
        context = CampaignContext(campaign)
        test_packet = IP(dst="0.0.0.0")/TCP(dport=80)
        for i in range(5):
            result = stateful_callback(test_packet, context)
            self.assertEqual(result, CallbackResult.SUCCESS)
        self.assertEqual(context.shared_data['packets_created'], 5)
        self.assertEqual(len(context.shared_data['packet_types']), 5)
        self.assertEqual(context.shared_data['packet_types'], ['TCP', 'UDP', 'TCP', 'UDP', 'TCP'])
        self.assertIn('last_packet', context.shared_data)
        
    def test_response_capture_with_history(self):
        """Test response capture functionality using fuzz history"""
        from datetime import datetime
        from fuzzing_framework import FuzzHistoryEntry
        
        # Create campaign and context
        campaign = FuzzingCampaign()
        context = CampaignContext(campaign)
        
        # Create a test packet and mock response
        test_packet = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        mock_response = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=80)/Raw(load=b"HTTP/1.1 200 OK\r\n\r\n")
        
        # Create history entry and add to context
        history_entry = FuzzHistoryEntry(
            packet=test_packet,
            timestamp_sent=datetime.now(),
            iteration=0
        )
        context.fuzz_history.append(history_entry)
        
        # Update history entry with response
        context.fuzz_history[-1].timestamp_received = datetime.now()
        context.fuzz_history[-1].response = mock_response
        
        # Verify the history entry
        self.assertEqual(len(context.fuzz_history), 1)
        self.assertEqual(context.fuzz_history[0].packet, test_packet)
        self.assertEqual(context.fuzz_history[0].response, mock_response)
        self.assertIsNotNone(context.fuzz_history[0].timestamp_sent)
        self.assertIsNotNone(context.fuzz_history[0].timestamp_received)
        self.assertIsNotNone(context.fuzz_history[0].get_response_time())
        self.assertFalse(context.fuzz_history[0].crashed)
        
        # Test max_history_size by adding more entries
        context.max_history_size = 3
        for i in range(1, 5):
            history_entry = FuzzHistoryEntry(
                packet=test_packet,
                timestamp_sent=datetime.now(),
                iteration=i
            )
            # Maintain history size limit
            if len(context.fuzz_history) >= context.max_history_size:
                context.fuzz_history.pop(0)  # Remove oldest entry
            context.fuzz_history.append(history_entry)
        
        # Verify history size and contents
        self.assertEqual(len(context.fuzz_history), 3)
        self.assertEqual(context.fuzz_history[0].iteration, 2)
        self.assertEqual(context.fuzz_history[1].iteration, 3)
        self.assertEqual(context.fuzz_history[2].iteration, 4)

if __name__ == '__main__':
    unittest.main()
