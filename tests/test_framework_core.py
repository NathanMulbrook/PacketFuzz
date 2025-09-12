#!/usr/bin/env python3
"""
Core Framework Tests for PacketFuzz

This test suite validates the core fuzzing framework functionality 
without dependency on external packet libraries.
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz import FuzzingCampaign, FuzzConfig
from packetfuzz.socket_types import SocketType


class TestFrameworkCore(unittest.TestCase):
    """Test core framework functionality"""
    
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
    
    def test_campaign_creation_and_attributes(self):
        """Test basic campaign creation with required attributes"""
        class TestCampaign(FuzzingCampaign):
            target = "127.0.0.1"
            socket_type = SocketType.RAW_UDP
            
            def packets(self):
                return [b"test_packet_data"]
        
        campaign = TestCampaign()
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.target, "127.0.0.1")
        self.assertEqual(campaign.socket_type, SocketType.RAW_UDP)
        
        # Test packets method
        packets = campaign.packets()
        self.assertIsInstance(packets, list)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0], b"test_packet_data")
    
    def test_campaign_inheritance(self):
        """Test campaign inheritance and method overriding"""
        class BaseCampaign(FuzzingCampaign):
            target = "127.0.0.1"
            socket_type = SocketType.RAW_TCP
            
            def packets(self):
                return [b"base_packet"]
            
            def validate_response(self, response):
                return len(response) > 0
        
        class ExtendedCampaign(BaseCampaign):
            def packets(self):
                base_packets = super().packets()
                extended_packets = [b"extended_packet"]
                return base_packets + extended_packets
        
        base_campaign = BaseCampaign()
        base_packets = base_campaign.packets()
        self.assertEqual(len(base_packets), 1)
        self.assertEqual(base_packets[0], b"base_packet")
        
        extended_campaign = ExtendedCampaign()
        extended_packets = extended_campaign.packets()
        self.assertEqual(len(extended_packets), 2)
        self.assertEqual(extended_packets[0], b"base_packet")
        self.assertEqual(extended_packets[1], b"extended_packet")
    
    def test_multiple_socket_types(self):
        """Test campaigns with different socket types"""
        # Test UDP socket campaign
        class UDPCampaign(FuzzingCampaign):
            target = "udp.test"
            socket_type = SocketType.MANAGED_UDP
            
            def packets(self):
                return [b"packet_for_UDP"]
        
        udp_campaign = UDPCampaign()
        self.assertEqual(udp_campaign.socket_type, SocketType.MANAGED_UDP)
        self.assertEqual(udp_campaign.target, "udp.test")
        
        # Test TCP socket campaign
        class TCPCampaign(FuzzingCampaign):
            target = "tcp.test"
            socket_type = SocketType.MANAGED_TCP
            
            def packets(self):
                return [b"packet_for_TCP"]
        
        tcp_campaign = TCPCampaign()
        self.assertEqual(tcp_campaign.socket_type, SocketType.MANAGED_TCP)
        self.assertEqual(tcp_campaign.target, "tcp.test")
        
        # Test Raw UDP campaign
        class RawUDPCampaign(FuzzingCampaign):
            target = "raw_udp.test"
            socket_type = SocketType.RAW_UDP
            
            def packets(self):
                return [b"packet_for_RAW_UDP"]
        
        raw_udp_campaign = RawUDPCampaign()
        self.assertEqual(raw_udp_campaign.socket_type, SocketType.RAW_UDP)
        self.assertEqual(raw_udp_campaign.target, "raw_udp.test")
    
    def test_validation_methods(self):
        """Test campaign validation and response handling"""
        class ValidatingCampaign(FuzzingCampaign):
            target = "validation.test"
            socket_type = SocketType.MANAGED_UDP
            
            def packets(self):
                return [b"validation_packet"]
            
            def validate_response(self, response):
                # Simple validation: response should be bytes and non-empty
                return isinstance(response, bytes) and len(response) > 0
        
        campaign = ValidatingCampaign()
        
        # Test validation with valid response
        valid_response = b"HTTP/1.1 200 OK\r\n\r\n"
        self.assertTrue(campaign.validate_response(valid_response))
        
        # Test validation with invalid responses
        self.assertFalse(campaign.validate_response(b""))
        self.assertFalse(campaign.validate_response("string response"))
        self.assertFalse(campaign.validate_response(None))
    
    def test_http_protocol_simulation(self):
        """Test HTTP protocol fuzzing simulation"""
        class HTTPFuzzCampaign(FuzzingCampaign):
            target = "127.0.0.1"
            socket_type = SocketType.MANAGED_TCP
            
            def packets(self):
                return [
                    b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
                    b"POST /data HTTP/1.1\r\nContent-Length: 4\r\n\r\ntest",
                    b"PUT /resource HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                    b"DELETE /item HTTP/1.1\r\n\r\n"
                ]
            
            def validate_response(self, response):
                # HTTP responses should start with HTTP version
                return (isinstance(response, bytes) and 
                        response.startswith(b"HTTP/"))
        
        campaign = HTTPFuzzCampaign()
        packets = campaign.packets()
        self.assertEqual(len(packets), 4)
        
        # Verify each packet is a valid HTTP request format
        for packet in packets:
            self.assertIn(b"HTTP/1.1", packet)
            self.assertTrue(packet.endswith(b"\r\n\r\n") or 
                          packet.endswith(b"\r\n\r\ntest"))
        
        # Test validation
        valid_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        self.assertTrue(campaign.validate_response(valid_response))
        
        invalid_response = b"Invalid response"
        self.assertFalse(campaign.validate_response(invalid_response))
    
    def test_dns_protocol_simulation(self):
        """Test DNS protocol fuzzing simulation"""
        class DNSFuzzCampaign(FuzzingCampaign):
            target = "8.8.8.8"
            socket_type = SocketType.MANAGED_UDP
            
            def packets(self):
                # Simulate DNS query packets (simplified)
                return [
                    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                    b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x07example\x03com\x00\x00\x01\x00\x01",
                ]
        
        campaign = DNSFuzzCampaign()
        self.assertEqual(campaign.target, "8.8.8.8")
        self.assertEqual(campaign.socket_type, SocketType.MANAGED_UDP)
        
        packets = campaign.packets()
        self.assertEqual(len(packets), 2)
        
        # DNS packets should contain domain names
        self.assertIn(b"example", packets[0])
        self.assertIn(b"test", packets[1])
    
    def test_campaign_with_custom_configuration(self):
        """Test campaign with custom configuration attributes"""
        class CustomConfigCampaign(FuzzingCampaign):
            target = "custom.test"
            socket_type = SocketType.RAW_IP
            port = 9999
            protocol = "CUSTOM"
            timeout = 30
            
            def packets(self):
                return [f"CUSTOM_PROTO port={self.port}".encode()]
            
            def get_config(self):
                return {
                    'target': self.target,
                    'socket_type': self.socket_type,
                    'port': self.port,
                    'protocol': self.protocol,
                    'timeout': self.timeout
                }
        
        campaign = CustomConfigCampaign()
        config = campaign.get_config()
        
        self.assertEqual(config['target'], "custom.test")
        self.assertEqual(config['socket_type'], SocketType.RAW_IP)
        self.assertEqual(config['port'], 9999)
        self.assertEqual(config['protocol'], "CUSTOM")
        self.assertEqual(config['timeout'], 30)
        
        packets = campaign.packets()
        self.assertIn(b"port=9999", packets[0])


if __name__ == '__main__':
    unittest.main()
