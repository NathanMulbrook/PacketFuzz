"""
PCAPFuzz: PCAP-based fuzzing utility for regression testing with advanced mutation options.

This utility enables PCAP-based fuzzing for regression testing scenarios. It can:

1. **Layer Extraction**: Extract specific layers from PCAP packets
    - When extract_at_layer="UDP", extracts the UDP payload (everything after UDP header)
    - When extract_at_layer="TCP", extracts the TCP payload (everything after TCP header)  
    - When extract_at_layer="IP", extracts the complete IP packet including all layers within
    - When extract_at_layer="Ethernet", extracts the complete Ethernet frame

2. **Payload Repackaging**: Wrap extracted payloads in new packet structures
    - repackage_template=IP()/UDP() wraps payload in provided headers for testing
    - repackage_template=IP()/TCP() wraps payload in provided headers for testing
    - repackage_template=IP() wraps payload in new IP header only

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
    campaign.extract_at_layer = "TCP"
    campaign.repackage_template = IP()/TCP()
    campaign.fuzz_mode = "field"  # Use dictionary-based field fuzzing
    campaign.execute()
"""

# Standard library imports
import logging
import os
from pathlib import Path
from typing import Callable, List, Optional

# Third-party imports
from scapy.all import Raw, rdpcap, sendp
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# Local imports
from .fuzzing_framework import CallbackResult, CampaignContext, FuzzingCampaign
from .mutator_manager import FuzzConfig, FuzzMode, MutatorManager
from .utils.packet_processing import PacketProcessingConfig, process_packet

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
    fuzz_mode: str = "field"                    # "field", "binary", "both", or "none"
    
    def __init__(self):
        super().__init__()
        # Override default target and packet since we'll get them from PCAP
        self.target = "192.168.1.100"  # Default target, can be overridden
        self.packet = None  # Will be set dynamically from PCAP files
        self.append_pcap = True  # PCAP campaigns aggregate multiple packets, so use append mode
        
        # Initialize packet processing configuration and attributes
        self._processing_config = PacketProcessingConfig()
        self._extract_at_layer: Optional[str] = None      # e.g., "UDP", "TCP", "IP", "Ethernet"
        self._include_layers: Optional[List[str]] = None  # e.g., ["HTTP", "DNS"] - only these layers
        self._exclude_layers: Optional[List[str]] = None  # e.g., ["Raw"] - exclude these layers
        self._repackage_template: Optional[Packet] = None # e.g., IP(dst="192.168.1.1") / UDP(dport=53)
    
    # Properties for configuration attributes that sync with processing config
    @property
    def extract_at_layer(self) -> Optional[str]:
        return self._extract_at_layer
    
    @extract_at_layer.setter
    def extract_at_layer(self, value: Optional[str]) -> None:
        self._extract_at_layer = value
        self._processing_config.extract_at_layer = value
    
    @property
    def include_layers(self) -> Optional[List[str]]:
        return self._include_layers
    
    @include_layers.setter
    def include_layers(self, value: Optional[List[str]]) -> None:
        self._include_layers = value
        self._processing_config.include_layers = value
    
    @property
    def exclude_layers(self) -> Optional[List[str]]:
        return self._exclude_layers
    
    @exclude_layers.setter
    def exclude_layers(self, value: Optional[List[str]]) -> None:
        self._exclude_layers = value
        self._processing_config.exclude_layers = value
    
    @property
    def repackage_template(self) -> Optional[Packet]:
        return self._repackage_template
    
    @repackage_template.setter
    def repackage_template(self, value: Optional[Packet]) -> None:
        self._repackage_template = value
        self._processing_config.repackage_template = value

    # Backward-compatibility accessors for legacy example/config attributes
    # Legacy: extract_layer -> Current: extract_at_layer
    @property
    def extract_layer(self) -> Optional[str]:  # type: ignore[override]
        return self.extract_at_layer

    @extract_layer.setter
    def extract_layer(self, value: Optional[str]) -> None:
        self.extract_at_layer = value

    # Legacy: repackage_in (string like "IP/UDP") -> Current: repackage_template (Packet)
    @property
    def repackage_in(self) -> Optional[str]:  # type: ignore[override]
        # Best-effort stringify of current template
        tpl = getattr(self, 'repackage_template', None)
        if tpl is None:
            return None
        names = []
        cur = tpl
        # Walk layer names
        while cur is not None:
            try:
                names.append(cur.name)
                cur = cur.payload if cur.payload else None
            except Exception:
                break
        return "/".join(names) if names else None

    @repackage_in.setter
    def repackage_in(self, value: Optional[str]) -> None:
        # Map simple strings to common templates for compatibility with examples
        if value is None:
            self.repackage_template = None
            return
        v = value.upper().strip()
        try:
            if v == "IP/UDP":
                template = IP()/UDP()
            elif v == "IP/TCP":
                template = IP()/TCP()
            elif v == "IP":
                template = IP()
            else:
                # Unknown string; leave unset so payload passes through unchanged
                template = None
            self.repackage_template = template
        except Exception:
            self.repackage_template = None
    
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
        # Use utility function for packet processing
        return process_packet(original_pkt, self._processing_config)
    
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
            # Determine sending strategy:
            # - If iterations is 0 or None: send each processed packet exactly once
            # - If iterations > 0: send that many total packets, cycling through processed packets if needed
            any_success = False
            n = len(all_processed_packets)
            
            if not self.iterations or self.iterations == 0:
                # Send each packet from PCAP exactly once
                packets_to_send = all_processed_packets
                iterations_per_packet = 1
            else:
                # Send total of self.iterations packets, cycling through PCAP if needed
                packets_to_send = [all_processed_packets[i % n] for i in range(self.iterations)]
                iterations_per_packet = 1
            
            # Temporarily override iterations for the base fuzzing loop
            original_iterations = self.iterations
            self.iterations = iterations_per_packet
            
            for pkt in packets_to_send:
                if self.context and not self.context.is_running:
                    break  # Stop if campaign is halted externally
                # Use the base class's fuzzing loop for sending, mutation, and callbacks
                success = super()._run_fuzzing_loop(fuzzer, pkt)
                any_success = any_success or success
            
            # Restore original iterations value
            self.iterations = original_iterations
            return any_success
        except Exception as e:
            logger.error(f"PCAP campaign execution failed: {e}")
            return False

# Standalone utility function for backwards compatibility
def pcap_fuzz(pcap_folder: str, extract_at_layer: Optional[str] = None, **kwargs):
    """
    Simple wrapper for PcapFuzzCampaign functionality.
    
    Args:
        pcap_folder: Path to folder containing PCAP files
        extract_at_layer: Layer to extract at ("UDP", "TCP", "IP", "Ethernet")
        **kwargs: Additional campaign configuration options
    """
    campaign = PcapFuzzCampaign()
    campaign.pcap_folder = pcap_folder
    campaign.extract_at_layer = extract_at_layer
    for key, value in kwargs.items():
        if hasattr(campaign, key):
            setattr(campaign, key, value)
    return campaign.execute()  # Use standard campaign execution
