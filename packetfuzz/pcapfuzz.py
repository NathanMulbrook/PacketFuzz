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

from scapy.all import rdpcap, sendp, Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from .mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from .fuzzing_framework import FuzzingCampaign, CallbackResult, CampaignContext
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
    extract_at_layer: Optional[str] = None      # e.g., "UDP", "TCP", "IP", "Ethernet"
    include_layers: Optional[List[str]] = None  # e.g., ["HTTP", "DNS"] - only these layers
    exclude_layers: Optional[List[str]] = None  # e.g., ["Raw"] - exclude these layers
    repackage_template: Optional[Packet] = None # e.g., IP(dst="192.168.1.1") / UDP(dport=53)
    fuzz_mode: str = "field"                    # "field", "binary", "both", or "none"
    
    def __init__(self):
        super().__init__()
        # Override default target and packet since we'll get them from PCAP
        self.target = "192.168.1.100"  # Default target, can be overridden
        self.packet = None  # Will be set dynamically from PCAP files
        self.append_pcap = True  # PCAP campaigns aggregate multiple packets, so use append mode

    # Backward-compatibility accessors for legacy example/config attributes
    # Legacy: extract_layer -> Current: extract_at_layer
    @property
    def extract_layer(self) -> Optional[str]:  # type: ignore[override]
        return getattr(self, 'extract_at_layer', None)

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
                self.repackage_template = IP()/UDP()
            elif v == "IP/TCP":
                self.repackage_template = IP()/TCP()
            elif v == "IP":
                self.repackage_template = IP()
            else:
                # Unknown string; leave unset so payload passes through unchanged
                self.repackage_template = None
        except Exception:
            self.repackage_template = None
    
    def _extract_layers(self, packet: Packet) -> Optional[Packet]:
        """
        Extract layers based on extraction rules.
        
        Args:
            packet: The packet to extract from
            
        Returns:
            The extracted layers or None if extraction failed
        """
        # Step 1: Find extraction point
        if self.extract_at_layer:
            layer = packet
            while layer and layer.name != self.extract_at_layer:
                layer = layer.payload
            if not layer or layer.name != self.extract_at_layer:
                return None
            extracted = layer.payload if layer.payload else None
        else:
            extracted = packet
        
        if not extracted:
            return None
        
        # Step 2: Apply include/exclude filters
        if self.include_layers:
            result = self._filter_include_layers(extracted, self.include_layers)
        elif self.exclude_layers:
            result = self._filter_exclude_layers(extracted, self.exclude_layers)
        else:
            result = extracted
        
        return result
    
    def _filter_include_layers(self, packet: Packet, include: List[str]) -> Optional[Packet]:
        """Keep only specified layers."""
        current = packet
        result = None
        
        while current:
            if current.name in include:
                if result is None:
                    result = current.copy()
                    result.payload = None
                else:
                    tail = result
                    while tail.payload:
                        tail = tail.payload
                    tail.payload = current.copy()
                    tail.payload.payload = None
            current = current.payload
        
        return result
    
    def _filter_exclude_layers(self, packet: Packet, exclude: List[str]) -> Optional[Packet]:
        """Remove specified layers."""
        if packet.name in exclude:
            return self._filter_exclude_layers(packet.payload, exclude) if packet.payload else None
        
        result = packet.copy()
        result.payload = None
        
        if packet.payload:
            filtered_payload = self._filter_exclude_layers(packet.payload, exclude)
            if filtered_payload:
                result.payload = filtered_payload
        
        return result
    
    def _repackage_payload(self, payload: Packet, template: Optional[Packet]) -> Packet:
        """
        Repackage extracted payload using user-provided template.
        
        Args:
            payload: The extracted payload to repackage
            template: The packet template to wrap the payload in (or None for no repackaging)
            
        Returns:
            The repackaged packet or original payload if no template
        """
        if template is None:
            return payload
            
        repackaged = template.copy()
        # Find the deepest layer in template and attach payload
        tail = repackaged
        while tail.payload:
            tail = tail.payload
        tail.payload = payload
        return repackaged
    
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
        
        # Step 1: Extract layers if specified
        if self.extract_at_layer or self.include_layers or self.exclude_layers:
            extracted = self._extract_layers(pkt)
            if not extracted:
                return None
            pkt = extracted
        
        # Step 2: Repackage if specified
        if self.repackage_template:
            pkt = self._repackage_payload(pkt, self.repackage_template)
        
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
