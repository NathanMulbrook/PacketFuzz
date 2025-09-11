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

# Bind custom protocol to UDP port 12345
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

# Bind RPC protocol layers
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

class ProtocolStateMachineCampaign(FuzzingCampaign):
    """Demonstrate stateful protocol fuzzing."""
    name = "Protocol State Machine Fuzzing"
    socket_config = RawIPConfig(target="192.168.1.100")
    iterations = 20
    output_network = False
    output_pcap = "state_machine_fuzz.pcap"
    verbose = True
    
    def __init__(self):
        super().__init__()
        self.state = "INIT"
        self.session_id = 1
    
    def generate_packet(self, iteration):
        """Generate packets based on protocol state."""
        if self.state == "INIT":
            # Send connection request
            self.state = "CONNECTING"
            return (IP() / UDP(dport=12345) / 
                   SimpleMessageProtocol(
                       version=1,
                       message_type=1,  # CONNECT
                       sequence_id=0,
                       data=f"SESSION_INIT_{self.session_id}".encode()
                   ))
        
        elif self.state == "CONNECTING":
            # Send authentication
            self.state = "AUTHENTICATING"
            import random
            auth_values = [
                b"user:password",
                b"admin:admin",
                b"",  # Empty auth
                b"A" * 100,  # Long auth
                b"user\x00password"  # Null byte injection
            ]
            return (IP() / UDP(dport=12345) / 
                   SimpleMessageProtocol(
                       version=1,
                       message_type=2,  # AUTH
                       sequence_id=1,
                       data=random.choice(auth_values)
                   ))
        
        elif self.state == "AUTHENTICATING":
            # Send data request
            self.state = "CONNECTED"
            import random
            request_values = [
                b"GET /data",
                b"GET /" + b"A" * 1000,  # Path overflow
                b"DELETE /system",  # Dangerous operation
                b"GET \x00\x01\x02"  # Binary injection
            ]
            return (IP() / UDP(dport=12345) / 
                   SimpleMessageProtocol(
                       version=1,
                       message_type=3,  # DATA_REQUEST
                       sequence_id=2,
                       data=random.choice(request_values)
                   ))
        
        else:  # CONNECTED
            # Send disconnect or reset state
            if iteration % 5 == 0:
                self.state = "INIT"
                self.session_id += 1
            
            return (IP() / UDP(dport=12345) / 
                   SimpleMessageProtocol(
                       version=1,
                       message_type=4,  # DISCONNECT
                       sequence_id=3,
                       data=b"BYE"
                   ))
    
    def execute(self):
        """Custom execution for stateful fuzzing."""
        print(f"Starting {self.name}")
        
        for i in range(self.iterations):
            packet = self.generate_packet(i)
            print(f"State: {self.state}, Iteration: {i}")
            
            # In a real scenario, you would send the packet and analyze responses
            # For demo purposes, we just show the packet structure
            packet.show()  # Show packet details
            
            if self.output_pcap:
                # Write to pcap if specified
                from scapy.utils import wrpcap
                wrpcap(self.output_pcap, packet, append=True)

def demonstrate_protocol_parsing():
    """Demonstrate parsing of custom protocols."""
    print("Custom Protocol Parsing Demonstration")
    print("=" * 40)
    
    # Create sample packets
    smp_packet = (IP() / UDP(dport=12345) / 
                 SimpleMessageProtocol(version=1, message_type=2, 
                                     sequence_id=100, data=b"Hello"))
    
    rpc_packet = (IP() / TCP(dport=54321) / 
                 CustomRPCHeader(magic=0x52504301, version=1, operation=5,
                               request_id=42, data_length=11) /
                 CustomRPCData(data=b"test_data_1"))
    
    print("Simple Message Protocol packet:")
    smp_packet.show()
    
    print("\nCustom RPC Protocol packet:")
    rpc_packet.show()
    
    # Demonstrate field access
    print(f"\nSMP Data: {smp_packet[SimpleMessageProtocol].data}")
    print(f"RPC Operation: {rpc_packet[CustomRPCHeader].operation}")
    print(f"RPC Data: {rpc_packet[CustomRPCData].data}")

def main():
    """Run custom protocol fuzzing demonstration."""
    print("Custom Protocol Fuzzing Demonstration")
    print("=" * 50)
    
    # Demonstrate protocol parsing
    demonstrate_protocol_parsing()
    
    print("\n" + "=" * 50)
    print("Running Fuzzing Campaigns:")
    
    # Run Simple Message Protocol fuzzing
    print("\n1. Simple Message Protocol Fuzzing:")
    smp_campaign = SimpleProtocolFuzzCampaign()
    smp_campaign.execute()
    
    # Run RPC Protocol fuzzing
    print("\n2. Custom RPC Protocol Fuzzing:")
    rpc_campaign = RPCProtocolFuzzCampaign()
    rpc_campaign.execute()
    
    # Run stateful protocol fuzzing
    print("\n3. Stateful Protocol Fuzzing:")
    state_campaign = ProtocolStateMachineCampaign()
    state_campaign.execute()
    
    print("\nCustom protocol fuzzing complete!")
    print("Generated PCAP files:")
    print("- simple_protocol_fuzz.pcap")
    print("- rpc_protocol_fuzz.pcap") 
    print("- state_machine_fuzz.pcap")

# Campaign registry for framework discovery
CAMPAIGNS = [
    SimpleProtocolFuzzCampaign,
    RPCProtocolFuzzCampaign,
    ProtocolStateMachineCampaign
]

if __name__ == "__main__":
    main()
