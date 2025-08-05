"""
PCAPFuzz: PCAP-based fuzzing utility for regression testing with advanced mutation options.

This utility enables PCAP-based fuzzing for regression testing scenarios. It can:

1. **Layer Extraction**: Extract specific layers from PCAP packets
   - When extract_layer="UDP", extracts the UDP payload (everything after UDP header)
   - When extract_layer="TCP", extracts the TCP payload (everything after TCP header)  
   - When extract_layer="IP", extracts the complete IP packet including all layers within
   - When extract_layer="Ethernet", extracts the complete Ethernet frame

2. **Payload Repackaging**: Wrap extracted payloads in new packet structures
   - repackage_in="IP/UDP" wraps payload in new IP/UDP headers for testing
   - repackage_in="IP/TCP" wraps payload in new IP/TCP headers for testing
   - repackage_in="IP" wraps payload in new IP header only

3. **Multiple Fuzzing Modes**:
   - "field": Uses framework's field-level fuzzing with dictionaries and FuzzField configs
   - "binary": Binary-level packet mutation using libFuzzer mutation engine
   - "both": Combines field and binary fuzzing approaches
   - "none": No fuzzing - replays packets as-is for regression testing

4. **Campaign Integration**: Inherits from FuzzingCampaign for full framework compatibility
   - Uses all campaign callbacks (pre_send, post_send, crash, etc.)
   - Respects rate limiting, PCAP output, and all standard campaign features
   - Integrates with dictionary manager and field configuration system

Example Usage:
    # Extract HTTP payloads from TCP packets and fuzz them
    campaign = PcapFuzzCampaign()
    campaign.pcap_folder = "regression_samples/"
    campaign.extract_layer = "TCP"
    campaign.repackage_in = "IP/TCP" 
    campaign.fuzz_mode = "field"  # Use dictionary-based field fuzzing
    campaign.execute()  # Use standard campaign execution, not custom run()
"""

from scapy.all import rdpcap, sendp, Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from fuzzing_framework import FuzzingCampaign, CallbackResult, CampaignContext
from typing import Optional, Callable, List
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class PcapFuzzCampaign(FuzzingCampaign):
    """
    PCAP-based fuzzing campaign with multiple mutation strategies.
    
    This campaign reads PCAP files and applies various fuzzing strategies to the packets within.
    It supports layer extraction, payload repackaging, and different fuzzing modes while 
    maintaining full compatibility with the campaign framework.
    """
    
    # Configuration attributes
    pcap_folder: str = "regression_samples/"
    extract_layer: Optional[str] = None  # e.g., "UDP", "TCP", "IP", "Ethernet" 
    repackage_in: Optional[str] = None   # e.g., "IP/UDP", "IP/TCP", "IP"
    fuzz_mode: str = "field"             # "field", "binary", "both", or "none"
    
    def __init__(self):
        super().__init__()
        # Override default target and packet since we'll get them from PCAP
        self.target = "192.168.1.100"  # Default target, can be overridden
        self.packet = None  # Will be set dynamically from PCAP files
    
    def _extract_layer(self, packet: Packet, layer_name: str) -> Optional[Packet]:
        """
        Extract a specific layer from a packet.
        
        This method extracts layers and their payloads:
        - "UDP": Returns everything in the UDP payload field
        - "TCP": Returns everything in the TCP payload field  
        - "IP": Returns the complete IP packet including all layers within
        - "Ethernet": Returns the complete Ethernet frame
        
        Args:
            packet: The packet to extract from
            layer_name: Name of the layer to extract ("UDP", "TCP", "IP", "Ethernet")
            
        Returns:
            The extracted layer/payload or None if not found
        """
        layer = packet
        while layer and layer.name != layer_name:
            layer = layer.payload
        
        if layer and layer.name == layer_name:
            if layer_name in ["UDP", "TCP"]:
                # Return the payload of transport layers
                return layer.payload if layer.payload else None
            else:
                # Return the complete layer for network/link layers
                return layer
        return None
    
    def _repackage_payload(self, payload: Packet, wrapper: str) -> Packet:
        """
        Repackage extracted payload in new packet structure.
        
        Args:
            payload: The extracted payload to repackage
            wrapper: The wrapper format ("IP/UDP", "IP/TCP", "IP")
            
        Returns:
            The repackaged packet
        """
        if wrapper == "IP/UDP":
            return IP(dst=str(self.target)) / UDP(dport=80) / payload
        elif wrapper == "IP/TCP":
            return IP(dst=str(self.target)) / TCP(dport=80) / payload
        elif wrapper == "IP":
            return IP(dst=str(self.target)) / payload
        else:
            return payload
    
    def _convert_to_scapy(self, data: bytes) -> Packet:
        """Convert raw bytes back to Scapy packet for field-aware fuzzing."""
        try:
            #TODO Update this to be more extensive and attempt to parse more protocols, this should attempt to return as much as possible in a capy packet
            # Try to parse as common packet types
            pkt = IP(data)  # Most common case
            return pkt
        except:
            try:
                # Fallback to raw packet
                return Raw(data)
            except:
                return Raw(data)
    
    def get_packet_with_embedded_config(self) -> Optional[Packet]:
        """
        Override the base campaign method to provide packets from PCAP files.
        
        For validation purposes, return a dummy packet. The actual PCAP processing
        happens in _run_fuzzing_loop().
        """
        # Return a dummy packet for validation - actual packets come from PCAP files
        return IP(dst=str(self.target)) / TCP(dport=80) / Raw(load=b"PCAP-based fuzzing")
    
    def _process_packet(self, original_pkt: Packet) -> Optional[Packet]:
        """
        Process a single packet according to extraction and repackaging configuration.
        
        Args:
            original_pkt: The original packet from PCAP
            
        Returns:
            The processed packet ready for fuzzing, or None if processing failed
        """
        pkt = original_pkt
        
        # Step 1: Extract layer if specified
        if self.extract_layer:
            extracted = self._extract_layer(pkt, self.extract_layer)
            if not extracted:
                return None
            pkt = extracted
        
        # Step 2: Repackage if specified
        if self.repackage_in:
            pkt = self._repackage_payload(pkt, self.repackage_in)
        
        # Step 3: Convert to Scapy object if working with raw data
        if isinstance(pkt, bytes):
            pkt = self._convert_to_scapy(pkt)
        
        return pkt
    
    def execute(self):
        """
        Execute the PCAP-based fuzzing campaign using the base class fuzzing loop for each processed/fuzzed packet.
        Iterations controls total number of packets sent. If iterations==0, process all packets once. If >0, loop over all packets until total sent == iterations.
        """
        try:
            # Ensure campaign context is initialized
            self.context = self.context or CampaignContext(self)
            # Create the fuzzer instance for this campaign
            fuzzer = self.create_fuzzer()
            pcap_folder = Path(self.pcap_folder)
            if not pcap_folder.exists():
                logger.warning(f"PCAP folder not found: {self.pcap_folder}")
                return False
            # Gather all processed packets from all pcaps (no fuzzing here)
            all_processed_packets = []
            for fname in sorted(pcap_folder.iterdir()):
                if fname.suffix != ".pcap":
                    continue  # Skip non-PCAP files
                logger.info(f"Processing PCAP file: {fname.name}")
                packets = rdpcap(str(fname))
                for original_pkt in packets:
                    processed_packet = self._process_packet(original_pkt)
                    if not processed_packet:
                        continue  # Skip packets that fail processing
                    all_processed_packets.append(processed_packet)
            if not all_processed_packets:
                logger.warning("No packets found in PCAP(s) after processing.")
                return False
            total_to_send = self.iterations or 0  # 0 means single pass
            any_success = False
            n = len(all_processed_packets)
            if total_to_send == 0:
                # Send each packet once (single pass)
                packets_to_send = all_processed_packets
            else:
                # Repeat packets as needed to reach total_to_send
                packets_to_send = (all_processed_packets[i % n] for i in range(total_to_send))
            for pkt in packets_to_send:
                if self.context and not self.context.is_running:
                    break  # Stop if campaign is halted externally
                # Use the base class's fuzzing loop for sending, mutation, and callbacks
                success = super()._run_fuzzing_loop(fuzzer, pkt)
                any_success = any_success or success
            return any_success
        except Exception as e:
            logger.error(f"PCAP campaign execution failed: {e}")
            return False

# Standalone utility function for backwards compatibility
def pcap_fuzz(pcap_folder: str, extract_layer: Optional[str] = None, **kwargs):
    """
    Simple wrapper for PcapFuzzCampaign functionality.
    
    Args:
        pcap_folder: Path to folder containing PCAP files
        extract_layer: Layer to extract ("UDP", "TCP", "IP", "Ethernet")
        **kwargs: Additional campaign configuration options
    """
    campaign = PcapFuzzCampaign()
    campaign.pcap_folder = pcap_folder
    campaign.extract_layer = extract_layer
    for key, value in kwargs.items():
        if hasattr(campaign, key):
            setattr(campaign, key, value)
    return campaign.execute()  # Use standard campaign execution
