#!/usr/bin/env python3
"""
Callback System Demo - Interactive Demonstration

This demo shows how to use the callback system to monitor fuzzing progress,
analyze responses, and implement custom logic during campaigns.
"""

import time
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from fuzzing_framework import FuzzingCampaign, FuzzField
from pcapfuzz import PcapFuzzCampaign

# Custom callback functions
def progress_callback(packet, iteration):
    """Show fuzzing progress with packet details."""
    print(f"### Iteration {iteration}: Fuzzing packet {packet.summary()}")
    
    # Show fuzzed fields
    if hasattr(packet, 'show'):
        # Don't actually show - just indicate what we're fuzzing
        pass
    
def response_analyzer(request, response, iteration):
    """Analyze responses and detect interesting patterns."""
    if response:
        print(f"### Response received: {response.summary()}")
        
        # Analyze response size
        if len(response) > 1000:
            print(f"   [LARGE] Large response detected: {len(response)} bytes")
        
        # Check for error indicators
        if response.haslayer(ICMP):
            icmp_layer = response[ICMP]
            if icmp_layer.type == 3:  # Destination Unreachable
                print(f"   [ICMP] Destination Unreachable: code {icmp_layer.code}")
        
        # TCP analysis
        if response.haslayer(TCP):
            tcp_layer = response[TCP]
            if tcp_layer.flags & 0x04:  # RST flag
                print(f"   [TCP] Reset received")
            elif tcp_layer.flags & 0x12:  # SYN-ACK
                print(f"   [TCP] SYN-ACK received - port open")
    else:
        print(f"   [TIMEOUT] No response (timeout)")

def error_handler(packet, error, iteration):
    """Handle errors during fuzzing."""
    print(f"[ERROR] Error in iteration {iteration}: {error}")
    print(f"   Packet: {packet.summary()}")
    
    # Log detailed error info
    import traceback
    print(f"   Details: {traceback.format_exc()}")

def campaign_start_callback(campaign):
    """Called when campaign starts."""
    print(f"[START] Starting campaign: {campaign.__class__.__name__}")
    print(f"   Target: {campaign.target}")
    print(f"   Iterations: {campaign.iterations}")
    print(f"   Rate limit: {campaign.rate_limit_per_second} pps")

def campaign_end_callback(campaign, stats):
    """Called when campaign ends."""
    print(f"[END] Campaign completed: {campaign.__class__.__name__}")
    print(f"   Total packets sent: {stats.get('packets_sent', 0)}")
    print(f"   Responses received: {stats.get('responses_received', 0)}")
    print(f"   Errors encountered: {stats.get('errors', 0)}")
    print(f"   Duration: {stats.get('duration', 0):.2f} seconds")

class CallbackDemoCampaign(FuzzingCampaign):
    """Demo campaign with comprehensive callback usage."""
    
    target = "127.0.0.1"
    iterations = 5
    rate_limit_per_second = 2
    
    # Enable all callbacks
    progress_callback = progress_callback
    response_callback = response_analyzer  
    error_callback = error_handler
    campaign_start_callback = campaign_start_callback
    campaign_end_callback = campaign_end_callback
    
    # Simple HTTP-like packet for demo
    packet_template = IP(dst=target)/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    
    fuzz_fields = [
        ("TCP.dport", FuzzField(dictionaries=["fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/generic-names.txt"])),
        ("Raw.load", FuzzField(dictionaries=["fuzzdb/attack/http-protocol/http-protocol-urls.txt"]))
    ]

class PcapCallbackDemo(PcapFuzzCampaign):
    """PCAP-based campaign with callbacks."""
    
    target = "127.0.0.1"
    iterations = 3
    rate_limit_per_second = 1
    
    # Load from sample PCAP
    pcap_file = "dns_infrastructure_fuzz.pcap"
    fuzz_mode = "field"  # Use dictionary fuzzing
    
    # Add callbacks
    progress_callback = progress_callback
    response_callback = response_analyzer
    error_callback = error_handler

def interactive_demo():
    """Interactive demonstration of callback features."""
    print("=== Callback System Demo ===")
    print()
    print("This demo shows how callbacks work during fuzzing campaigns.")
    print("We'll run a short campaign with various callbacks enabled.")
    print()
    
    # Demo 1: Basic callback campaign
    print("Demo 1: Basic Campaign with Full Callbacks")
    print("-" * 50)
    
    campaign = CallbackDemoCampaign()
    
    # Show callback configuration
    print("Configured callbacks:")
    print(f"  - Progress tracking: {'YES' if campaign.progress_callback else 'NO'}")
    print(f"  - Response analysis: {'YES' if campaign.response_callback else 'NO'}")
    print(f"  - Error handling: {'YES' if campaign.error_callback else 'NO'}")
    print(f"  - Campaign lifecycle: {'YES' if campaign.campaign_start_callback else 'NO'}")
    print()
    
    try:
        # This would normally run the campaign
        # For demo purposes, we'll simulate it
        print("🔄 Running campaign (simulated)...")
        
        # Simulate campaign lifecycle
        campaign_start_callback(campaign)
        
        for i in range(1, campaign.iterations + 1):
            # Simulate packet creation and sending
            packet = campaign.packet_template
            progress_callback(packet, i)
            
            # Simulate response (sometimes none)
            if i % 2 == 0:
                # Create history entry for this iteration
            if hasattr(campaign, 'context') and campaign.context:
                from datetime import datetime
                from fuzzing_framework import FuzzHistoryEntry
                
                # Create and add history entry
                history_entry = FuzzHistoryEntry(
                    packet=packet,
                    timestamp_sent=datetime.now(),
                    iteration=i
                )
                
                # Manage history size
                if len(campaign.context.fuzz_history) >= campaign.context.max_history_size:
                    campaign.context.fuzz_history.pop(0)  # Remove oldest entry
                campaign.context.fuzz_history.append(history_entry)
            
            # Simulate response (sometimes none)
            if i % 2 == 0:
                # Create a mock response
                response = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=80, dport=12345)/Raw(load="HTTP/1.1 200 OK\r\n\r\n")
                
                # Update history with response
                if hasattr(campaign, 'context') and campaign.context and campaign.context.fuzz_history:
                    campaign.context.fuzz_history[-1].timestamp_received = datetime.now()
                    campaign.context.fuzz_history[-1].response = response
                    
                    # Show response time if available
                    resp_time = campaign.context.fuzz_history[-1].get_response_time()
                    if resp_time is not None:
                        print(f"   [TIMING] Response time: {resp_time:.2f} ms")
                
                response_analyzer(packet, response, i)
            else:
                response_analyzer(packet, None, i)
            
            # Simulate error (rare)
            if i == 3:
                error = Exception("Simulated error for demo purposes")
                error_handler(packet, error, i)
                
                # Mark history entry as crashed if available
                if hasattr(campaign, 'context') and campaign.context and campaign.context.fuzz_history:
                    campaign.context.fuzz_history[-1].crashed = True
            
            # Simulate rate limiting
            time.sleep(0.05)
            else:
                response_analyzer(packet, None, i)
            
            time.sleep(0.5)  # Rate limiting simulation
        
        # Simulate campaign end
        stats = {
            'packets_sent': campaign.iterations,
            'responses_received': campaign.iterations // 2,
            'errors': 0,
            'duration': campaign.iterations * 0.5
        }
        campaign_end_callback(campaign, stats)
        
    except Exception as e:
        error_handler(campaign.packet_template, str(e), 1)
    
    print()
    print("Demo 2: PCAP Campaign Callbacks")
    print("-" * 50)
    
    # Check if PCAP file exists
    import os
    if os.path.exists("dns_infrastructure_fuzz.pcap"):
        print("Loading PCAP-based campaign with callbacks...")
        pcap_campaign = PcapCallbackDemo()
        
        print(f"PCAP file: {pcap_campaign.pcap_file}")
        print(f"Fuzz mode: {pcap_campaign.fuzz_mode}")
        print("This would analyze the PCAP and fuzz based on captured packets.")
    else:
        print("⚠️  No sample PCAP file found - skipping PCAP demo")
    
    print()
    print("=== Demo Complete ===")
    print()
    print("Key takeaways:")
    print("• Callbacks provide visibility into fuzzing process")
    print("• Response analysis helps identify interesting behavior") 
    print("• Error handling prevents campaigns from crashing")
    print("• Progress tracking shows fuzzing status")
    print("• Campaign lifecycle callbacks provide start/end hooks")

if __name__ == "__main__":
    interactive_demo()
