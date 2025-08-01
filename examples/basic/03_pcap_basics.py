#!/usr/bin/env python3
"""
Basic PCAP Example - PCAP-Based Fuzzing and Regression Testing

This example shows how to use PCAP files for regression testing and fuzzing.
"""

import sys
import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pcapfuzz import PcapFuzzCampaign

class BasicRegressionCampaign(PcapFuzzCampaign):
    """Basic regression testing - replay packets without fuzzing."""
    name = "Basic Regression Test"
    pcap_folder = "regression_samples/"
    fuzz_mode = "none"  # No fuzzing - pure regression testing
    target = "192.168.1.100"
    output_network = False
    output_pcap = "regression_replay.pcap"
    verbose = True

class BasicPayloadExtractionCampaign(PcapFuzzCampaign):
    """Extract UDP payloads and fuzz them."""
    name = "UDP Payload Extraction"
    pcap_folder = "regression_samples/"
    extract_layer = "UDP"  # Extract UDP payload
    repackage_in = "IP/UDP"  # Repackage in new headers
    fuzz_mode = "field"  # Use dictionary-based fuzzing
    target = "192.168.1.100"
    iterations = 3
    output_network = False
    output_pcap = "udp_payload_fuzz.pcap"
    verbose = True

# List of PCAP campaigns
campaigns = [
    BasicRegressionCampaign,
    BasicPayloadExtractionCampaign
]
