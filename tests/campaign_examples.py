"""
Minimal example campaign file for CLI and test validation.
"""
from scapy.layers.inet import IP, TCP
from fuzzing_framework import FuzzingCampaign

class MinimalTestCampaign(FuzzingCampaign):
    name = "MinimalTestCampaign"
    target = "127.0.0.1"
    packet = IP(dst="127.0.0.1")/TCP(dport=80)
    iterations = 1
    output_network = False
    output_pcap = None

CAMPAIGNS = [MinimalTestCampaign]
