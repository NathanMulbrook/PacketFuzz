#!/usr/bin/env python3
"""
Advanced Example: Custom Protocols - Custom Protocol Definition and Fuzzing

Demonstrates how to define custom protocols with Scapy and integrate them
with the PacketFuzz framework for specialized protocol fuzzing.
"""

import sys
import os
from scapy.fields import ByteField, ShortField, IntField, StrLenField, FieldLenField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzField, CallbackResult

# Custom Protocol Definition: Simple Message Protocol (SMP)
class SimpleMessageProtocol(Packet):
    """Custom protocol for demonstration."""
    name = "SimpleMessageProtocol"
    fields_desc = [
        ByteField("version", 1),
        ByteField("message_type", 1),
        ShortField("sequence_id", 0),
        FieldLenField("payload_length", None, length_of="payload"),
        StrLenField("payload", b"", length_from=lambda pkt: pkt.payload_length)
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
    target = "192.168.1.100"
    iterations = 25
    output_network = False
    output_pcap = "simple_protocol_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() / 
        UDP(dport=12345) /
        SimpleMessageProtocol(
            version=FuzzField(values=[1, 2, 255]),  # Test version handling
            message_type=FuzzField(values=[0, 1, 2, 15, 255]),  # Various message types
            sequence_id=FuzzField(values=[0, 1, 65535]),  # Boundary values
            payload=FuzzField(values=[
                b"",  # Empty payload
                b"Hello, World!",  # Normal payload
                b"A" * 100,  # Large payload
                b"\x00\x01\x02\x03",  # Binary payload
                b"X" * 1000  # Very large payload
            ])
        )
    )
    
    def post_send_callback(self, context, packet, response=None):
        """Log custom protocol fuzzing results."""
        if packet.haslayer(SimpleMessageProtocol):
            smp = packet[SimpleMessageProtocol]
            print(f"Sent SMP: v{smp.version}, type={smp.message_type}, "
                  f"seq={smp.sequence_id}, payload_len={len(smp.payload)}")
        
        return CallbackResult.SUCCESS

class RPCProtocolFuzzCampaign(FuzzingCampaign):
    """Fuzz custom RPC protocol."""
    name = "Custom RPC Protocol Fuzzing"
    target = "192.168.1.100"
    iterations = 30
    output_network = False
    output_pcap = "rpc_protocol_fuzz.pcap"
    verbose = True
    
    packet = (
        IP() / 
        TCP(dport=54321) /
        CustomRPCHeader(
            magic=FuzzField(values=[
                0x52504301,  # Correct magic
                0x52504300,  # Wrong version
                0x00000000,  # Zero magic
                0xFFFFFFFF   # Invalid magic
            ]),
            version=FuzzField(values=[1, 2, 0, 255]),
            operation=FuzzField(values=[0, 1, 2, 10, 255]),
            request_id=FuzzField(values=[0, 1, 0xFFFF]),
            data_length=FuzzField(values=[0, 10, 100, 0xFFFF])
        ) /
        CustomRPCData(
            data=FuzzField(values=[
                b"",
                b"normal_data",
                b"A" * 50,
                b"\x00" * 20,
                b"malformed_json{invalid",
                b"X" * 200
            ])
        )
    )
    
    def pre_send_callback(self, context, packet):
        """Validate RPC packet consistency."""
        if packet.haslayer(CustomRPCHeader) and packet.haslayer(CustomRPCData):
            header = packet[CustomRPCHeader]
            data = packet[CustomRPCData]
            
            # Adjust data_length to match actual data for some packets
            if context.stats['packets_sent'] % 3 == 0:
                header.data_length = len(data.data)
        
        return CallbackResult.SUCCESS
    
    def post_send_callback(self, context, packet, response=None):
        """Log RPC protocol fuzzing results."""
        if packet.haslayer(CustomRPCHeader):
            rpc = packet[CustomRPCHeader]
            data_layer = packet[CustomRPCData] if packet.haslayer(CustomRPCData) else None
            actual_data_len = len(data_layer.data) if data_layer else 0
            
            print(f"Sent RPC: magic=0x{rpc.magic:08x}, op={rpc.operation}, "
                  f"req_id={rpc.request_id}, declared_len={rpc.data_length}, "
                  f"actual_len={actual_data_len}")
        
        return CallbackResult.SUCCESS

class ProtocolStateMachineCampaign(FuzzingCampaign):
    """Demonstrate stateful protocol fuzzing."""
    name = "Protocol State Machine Fuzzing"
    target = "192.168.1.100"
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
                       payload=f"SESSION_INIT_{self.session_id}".encode()
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
                       payload=random.choice(auth_values)
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
                       payload=random.choice(request_values)
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
                       payload=b"BYE"
                   ))
    
    def execute(self):
        """Custom execution for stateful fuzzing."""
        print(f"Starting {self.name}")
        
        for i in range(self.iterations):
            packet = self.generate_packet(i)
            print(f"State: {self.state}, Iteration: {i}")
            
            # In a real scenario, you would send the packet and analyze responses
            # For demo purposes, we just show the packet structure
            packet.show2()  # Show packet details
            
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
                                     sequence_id=100, payload=b"Hello"))
    
    rpc_packet = (IP() / TCP(dport=54321) / 
                 CustomRPCHeader(magic=0x52504301, version=1, operation=5,
                               request_id=42, data_length=11) /
                 CustomRPCData(data=b"test_data_1"))
    
    print("Simple Message Protocol packet:")
    smp_packet.show2()
    
    print("\nCustom RPC Protocol packet:")
    rpc_packet.show2()
    
    # Demonstrate field access
    print(f"\nSMP Payload: {smp_packet[SimpleMessageProtocol].payload}")
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
