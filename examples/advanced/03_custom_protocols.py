#!/usr/bin/env python3
"""
Custom Protocol Extension Examples

Demonstrates how to define custom protocols with Scapy and integrate them
with PacketFuzz for specialized protocol fuzzing:
- Custom Scapy protocol definition
- Protocol binding and layer integration
- Field-level configuration for custom fields
- Advanced protocol fuzzing patterns

Run with: python -m packetfuzz examples/advanced/03_custom_protocols.py --disable-network
"""

import sys
import os
from scapy.fields import ByteField, ShortField, IntField, StrLenField, FieldLenField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult
from packetfuzz.sockets.raw_ip_socket import RawIPConfig

# Custom Protocol Definition: Simple Message Protocol (SMP)
class SimpleMessageProtocol(Packet):
    """Custom protocol for demonstration."""
    name = "SimpleMessageProtocol"
    fields_desc = [
        ByteField("version", 1),
        ByteField("message_type", 1),
        ShortField("sequence_id", 0),
        FieldLenField("payload_length", None, length_of="data"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.payload_length)
    ]

bind_layers(UDP, SimpleMessageProtocol, dport=12345)
bind_layers(UDP, SimpleMessageProtocol, sport=12345)

# Custom Protocol Definition: Custom RPC Protocol
class CustomRPCHeader(Packet):
    """Custom RPC-like protocol header."""
    name = "CustomRPCHeader"
    fields_desc = [
        IntField("magic", 0x52504301),  # 'RPC\x01'
        ByteField("version", 1),
        ByteField("operation", 0),
        ShortField("request_id", 0),
        IntField("data_length", 0)
    ]

class CustomRPCData(Packet):
    """Custom RPC data payload."""
    name = "CustomRPCData"
    fields_desc = [
        StrLenField("data", b"", length_from=lambda pkt: pkt.underlayer.data_length if pkt.underlayer else 0)
    ]

bind_layers(CustomRPCHeader, CustomRPCData)
bind_layers(TCP, CustomRPCHeader, dport=54321)

class SimpleProtocolFuzzCampaign(FuzzingCampaign):
    """Fuzz custom Simple Message Protocol."""
    name = "Simple Message Protocol Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 15
    output_network = False
    output_pcap = "simple_protocol_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() / 
        UDP(dport=12345) /
        SimpleMessageProtocol(
            version=FuzzField(values=[1, 2, 255], description="Protocol versions"),
            message_type=FuzzField(values=[0, 1, 2, 15], description="Message types"),
            data=FuzzField(values=[
                b"Hello", b"Test", b"A"*100, b"\x00\x01\x02"
            ], description="Message payloads")
        )
    )
    
    def post_send_callback(self, context, packet, response=None):
        """Log custom protocol fuzzing results."""
        if packet.haslayer(SimpleMessageProtocol):
            smp = packet[SimpleMessageProtocol]
            print(f"Sent SMP: v{smp.version}, type={smp.message_type}, data_len={len(smp.data)}")
        return CallbackResult.SUCCESS

class RPCProtocolFuzzCampaign(FuzzingCampaign):
    """Fuzz custom RPC protocol."""
    name = "Custom RPC Protocol Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 20
    output_network = False
    output_pcap = "rpc_protocol_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() / 
        TCP(dport=54321) /
        CustomRPCHeader(
            magic=FuzzField(values=[0x52504301, 0x52504300, 0x00000000], 
                           description="RPC magic numbers"),
            operation=FuzzField(values=[0, 1, 2, 255], description="RPC operations"),
            data_length=FuzzField(values=[0, 10, 100], description="Data lengths")
        ) /
        CustomRPCData(
            data=FuzzField(values=[
                b"", b"normal_data", b"A"*50, b"\x00"*20
            ], description="RPC payloads")
        )
    )
    
    def post_send_callback(self, context, packet, response=None):
        """Log RPC protocol fuzzing results."""
        if packet.haslayer(CustomRPCHeader):
            rpc = packet[CustomRPCHeader]
            data_layer = packet[CustomRPCData] if packet.haslayer(CustomRPCData) else None
            actual_data_len = len(data_layer.data) if data_layer else 0
            
            print(f"Sent RPC: magic=0x{rpc.magic:08x}, op={rpc.operation}, "
                  f"declared_len={rpc.data_length}, actual_len={actual_data_len}")
        
        return CallbackResult.SUCCESS



CAMPAIGNS = [
    SimpleProtocolFuzzCampaign,
    RPCProtocolFuzzCampaign
    ]
