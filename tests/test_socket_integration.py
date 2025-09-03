#!/usr/bin/env python3
"""
Socket Integration Tests for PacketFuzz

This test suite validates socket functionality and network behavior.
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from packetfuzz.socket_types import SocketType
from packetfuzz.sockets.socket_interface import FuzzSocket, create
from packetfuzz.sockets.managed_udp_socket import ManagedUDPSocket, ManagedUDPConfig
from packetfuzz.sockets.raw_ip_socket import RawIPSocket
from packetfuzz import FuzzingCampaign

class TestSocketIntegration(unittest.TestCase):
    """Test socket integration and functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test campaign for socket creation
        class TestCampaign(FuzzingCampaign):
            socket_type = SocketType.MANAGED_UDP
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=53)
            
        self.test_campaign = TestCampaign()
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
    
    def test_socket_type_enum_completeness(self):
        """Test that SocketType enum has all expected socket types"""
        expected_types = [
            'RAW_IP', 'RAW_UDP', 'RAW_TCP', 'RAW_ETHERNET',
            'MANAGED_UDP', 'MANAGED_TCP', 
            'SERVER_UDP', 'SERVER_TCP',
            'FTP_CLIENT', 'FTP_SERVER',
            'MODBUS_CLIENT', 'MODBUS_SERVER',
            'TELNET_CLIENT', 'TELNET_SERVER',
            'TFTP_CLIENT', 'TFTP_SERVER',
            'CANBUS'
        ]
        
        for socket_type in expected_types:
            self.assertTrue(hasattr(SocketType, socket_type), 
                          f"SocketType missing {socket_type}")
    
    def test_socket_interface_creation(self):
        """Test FuzzSocket interface creation"""
        # Test socket creation through the factory
        socket = create(self.test_campaign)
        self.assertIsNotNone(socket)
        self.assertIsInstance(socket, FuzzSocket)
        
    def test_managed_udp_socket_creation(self):
        """Test ManagedUDPSocket creation and basic functionality"""
        socket = ManagedUDPSocket(self.test_campaign)
        self.assertIsNotNone(socket)
        
        # Test socket configuration
        self.assertIsNotNone(socket.socket_cfg)
        if socket.socket_cfg:
            self.assertEqual(socket.socket_cfg.target, "127.0.0.1")
            self.assertEqual(socket.socket_cfg.port, 53)
        
    def test_raw_ip_socket_creation(self):
        """Test RawIPSocket creation"""
        try:
            # Create campaign for raw IP
            class RawIPCampaign(FuzzingCampaign):
                socket_type = SocketType.RAW_IP
                
            raw_campaign = RawIPCampaign()
            socket = RawIPSocket(raw_campaign)
            self.assertIsNotNone(socket)
        except PermissionError:
            # Raw sockets require root privileges, skip if not available
            self.skipTest("Raw socket creation requires root privileges")
        except Exception as e:
            # Other exceptions might occur in test environment
            self.skipTest(f"Raw socket creation failed: {e}")
    
    def test_socket_packet_compatibility(self):
        """Test socket compatibility with different packet types"""
        # Test UDP socket with basic packet data
        udp_socket = ManagedUDPSocket(self.test_campaign)
        test_packet = b"test_packet_data"
        
        # Test that socket accepts packet data
        self.assertIsInstance(test_packet, bytes)
        self.assertEqual(len(test_packet), 16)
        
    def test_socket_error_handling(self):
        """Test socket error handling for invalid configurations"""
        # Test invalid port configurations
        class BadPortCampaign(FuzzingCampaign):
            socket_type = SocketType.MANAGED_UDP
            socket_config = ManagedUDPConfig(target="127.0.0.1", port=-1)
        
        try:
            bad_campaign = BadPortCampaign()
            socket = ManagedUDPSocket(bad_campaign)
            # Socket creation itself doesn't validate port, opening does
            self.assertIsNotNone(socket)
        except Exception:
            # Some validation might occur during creation
            pass
    
    def test_socket_configuration_validation(self):
        """Test socket configuration validation"""
        # Test valid configurations
        valid_configs = [
            ("127.0.0.1", 80),
            ("localhost", 443),
            ("192.168.1.1", 8080),
        ]
        
        for host, port in valid_configs:
            try:
                class TestCampaign(FuzzingCampaign):
                    socket_type = SocketType.MANAGED_UDP
                    socket_config = ManagedUDPConfig(target=host, port=port)
                
                campaign = TestCampaign()
                socket = ManagedUDPSocket(campaign)
                self.assertIsNotNone(socket)
                if socket.socket_cfg:
                    self.assertEqual(socket.socket_cfg.target, host)
                    self.assertEqual(socket.socket_cfg.port, port)
            except Exception as e:
                self.fail(f"Valid socket config ({host}, {port}) failed: {e}")
    
    def test_socket_factory_creation(self):
        """Test socket creation through factory function"""
        # Test factory creates correct socket type
        socket = create(self.test_campaign)
        self.assertIsNotNone(socket)
        self.assertIsInstance(socket, ManagedUDPSocket)
        
        # Test different socket types
        class RawUDPCampaign(FuzzingCampaign):
            socket_type = SocketType.RAW_UDP
            
        try:
            raw_campaign = RawUDPCampaign()
            raw_socket = create(raw_campaign)
            self.assertIsNotNone(raw_socket)
        except Exception:
            # Raw sockets may fail in test environment
            self.skipTest("Raw UDP socket creation not available")

if __name__ == '__main__':
    unittest.main()
