#!/usr/bin/env python3
"""
PacketFuzz Framework

This module provides a class-based framework for defining fuzzing campaigns,
similar to how Scapy defines packets and fields using class inheritance.

Integrates libFuzzer mutation engine with Scapy packet definitions and 
FuzzDB dictionaries for comprehensive network protocol fuzzing.

Now uses embedded packet configuration with field_fuzz() and fuzz_config() methods.
"""

# Standard library imports
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import logging
import os
import random
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Union

# Third-party imports
from scapy.layers.can import CAN
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw, fuzz
from scapy.sendrecv import send, sendp, sniff, sr1
from scapy.utils import wrpcap

# Local imports
from .mutator_manager import FuzzConfig, FuzzMode, MutatorManager, DEFAULT_FUZZ_WEIGHT, DEFAULT_MUTATOR_PREFERENCE
from .mutator_manager_data import MutatorManagerData
from .socket_types import SocketType
from .sockets.socket_interface import FuzzSocket
from .utils.packet_report import ReportingEngine, ReportLevel, write_crash_report, generate_campaign_reports, write_fuzz_history_dump
from .utils.scapy_utils import get_layer_names_from_packets, get_layer_name
from .default_mappings import FIELD_NAME_WEIGHTS, DEFAULT_FUZZ_WEIGHT_SCALING
from .utils.pattern_utils import parse_field_patterns, pattern_matches_any

# Constants
DEFAULT_PCAP_FILENAME = "fuzzing_session.pcap"
DEFAULT_ITERATIONS = 1000
DEFAULT_RATE_LIMIT = 500.0
DEFAULT_RESPONSE_TIMEOUT = 2.0
DEFAULT_STATS_INTERVAL = 10.0

# Centralized output directory structure
DEFAULT_ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
DEFAULT_PCAP_DIR = DEFAULT_ARTIFACTS_DIR / "pcaps"
DEFAULT_LOG_DIR = DEFAULT_ARTIFACTS_DIR / "logs"
DEFAULT_CRASH_LOG_DIR = DEFAULT_ARTIFACTS_DIR / "crash_logs"
DEFAULT_REPORT_DIR = "artifacts/reports"

FUZZ_CONFIG_INHERITANCE_MODE = "nearest"

# Default interface offload features to disable for malformed packet fuzzing
DEFAULT_OFFLOAD_FEATURES = [
    "tx-checksumming",      # Transmit checksum offloading
    "rx-checksumming",      # Receive checksum offloading  
    "tcp-segmentation-offload",  # TCP segmentation offload (TSO)
    "generic-segmentation-offload",  # Generic segmentation offload (GSO)
    "generic-receive-offload",   # Generic receive offload (GRO)
    "large-receive-offload"      # Large receive offload (LRO)
]

log_dir = Path(DEFAULT_LOG_DIR)
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except (OSError, IOError):
    print("[ERROR] Failed to create log directory. Please ensure permissions are correct.")
    raise SystemExit(2)

if not logging.getLogger().handlers:
    try:
        file_path = log_dir / 'packetfuzz.log'
        fh = logging.FileHandler(file_path)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[fh, logging.StreamHandler()]
        )
    except (OSError, IOError, PermissionError) as e:
        print(f"[ERROR] Failed to initialize file logging at {DEFAULT_LOG_DIR}/packetfuzz.log.")
        print("        Please ensure you have write permissions and no root-owned logs remain.")
        print(f"        Details: {e}")
        raise SystemExit(2)
logger = logging.getLogger(__name__)

# Install packet extensions for embedded configuration
from .packet_extensions import install_packet_extensions
install_packet_extensions()


class CallbackResult(Enum):
    """Standard return values for all callback functions"""
    SUCCESS = "success"          # Continue normally
    NO_SUCCESS = "no_success"    # Non-critical failure, continue with logging
    FAIL_CRASH = "fail_crash"    # Critical failure, trigger crash handling


@dataclass
class CrashInfo:
    """Standardized crash information passed to crash callbacks"""
    packet: Optional[Packet]
    crash_source: str  # "pre_launch", "pre_send", "post_send", "monitor"
    exception: Optional[Exception] = None
    context: Optional['CampaignContext'] = None
    timestamp: datetime = field(default_factory=datetime.now)
    crash_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Generate unique crash ID based on timestamp."""
        self.crash_id = f"crash_{self.timestamp.strftime('%Y%m%d_%H%M%S_%f')}"

@dataclass
class CampaignContext:
    """Shared context used to track certain runtime state information"""
    campaign: Any
    iteration: int = 0
    is_running: bool = True
    stats: dict = field(default_factory=lambda: {
        'packets_sent': 0,
        'callbacks_executed': 0,
        'no_success_count': 0,
        'crash_count': 0
    })
    shared_data: dict = field(default_factory=dict)  # User data sharing between callbacks, not used by framework
    start_time: float = field(default_factory=time.time)
    fuzz_history: List[FuzzHistoryEntry] = field(default_factory=list)
    max_history_size: int = 100000
    socket: Optional[socket.socket] = None  # Placeholder for raw socket object if needed (for backward compatibility)
    fuzz_socket: Optional[FuzzSocket] = None  # New: wrapper around raw socket
    mutator_data: Optional[MutatorManagerData] = None 
@dataclass
class FuzzHistoryEntry:
    """Tracks runtime execution data for a single fuzzing iteration (responses, failures, timing)"""
    # Core execution timing
    timestamp_sent: Optional[datetime] = None
    timestamp_received: Optional[datetime] = None
    iteration: int = -1 #This is probably not needed, but this can help with desync issues
    
    # Runtime results
    response: Optional[Any] = None
    crashed: bool = False
    crash_info: Optional[CrashInfo] = None
    
    # Serialization tracking (runtime execution data)
    packet_bytes: Optional[bytes] = None  # Serialized packet bytes that were actually sent
    serialization_failed: bool = False  # True if packet couldn't be serialized
    serialization_error: Optional[str] = None  # Error message if serialization failed
    
    # Network and protocol information (for reporting)
    
    # Payload information (derived from sent bytes)
    payload_size: Optional[int] = None
    payload_hash: Optional[str] = None  # Hash of the payload for deduplication
    
    # Response information (runtime results)
    response_size: Optional[int] = None
    response_status: Optional[str] = None  # HTTP status, error code, etc.
    response_headers: Optional[dict] = None  # For HTTP-like protocols
    
    # Campaign context (for reporting)
    # campaign_name and protocol are now omitted; derive from campaign or packet as needed
    test_case_id: Optional[str] = None  # User-defined test case identifier
    
    # Additional metadata
    notes: Optional[str] = None  # User or system notes about this iteration
    tags: List[str] = field(default_factory=list)  # Custom tags for categorization
    
    def get_response_time(self) -> Optional[float]:
        """Calculate response time in milliseconds if both timestamps are available"""
        if self.timestamp_sent and self.timestamp_received:
            delta = self.timestamp_received - self.timestamp_sent
            return delta.total_seconds() * 1000
        return None
    
    def get_packet_bytes(self) -> Optional[bytes]:
        """Get serialized packet bytes that were actually sent, not re-serialized data"""
        return self.packet_bytes
    
    def get_payload_hash(self) -> Optional[str]:
        """Generate hash of packet bytes for deduplication"""
        if self.payload_hash is not None:
            return self.payload_hash
        
        packet_bytes = self.get_packet_bytes()
        if packet_bytes:
            self.payload_hash = hashlib.sha256(packet_bytes).hexdigest()[:16]  # Short hash
            return self.payload_hash
        
        return None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization and reporting"""
        return {
            'iteration': self.iteration,
            'timestamp_sent': self.timestamp_sent.isoformat() if self.timestamp_sent else None,
            'timestamp_received': self.timestamp_received.isoformat() if self.timestamp_received else None,
            'response_time_ms': self.get_response_time(),
            'crashed': self.crashed,
            'serialization_failed': self.serialization_failed,
            'serialization_error': self.serialization_error,
            'payload_size': self.payload_size,
            'payload_hash': self.get_payload_hash(),
            'response_size': self.response_size,
            'response_status': self.response_status,
            'response_headers': self.response_headers,
            'test_case_id': self.test_case_id,
            'notes': self.notes,
            'tags': self.tags,
            'crash_id': self.crash_info.crash_id if self.crash_info else None,
            'crash_source': self.crash_info.crash_source if self.crash_info else None
        }

class CallbackManager:
    """
    Unified callback execution and management.
    Handles all user and internal callbacks with error handling.
    Logs crashes and invokes user crash callbacks.
    """
    
    def __init__(self, campaign: Any):
        """Initialize CallbackManager with campaign reference."""
        self.campaign = campaign
    
    def execute_callback(self, callback_func: Optional[Callable], callback_type: str, 
                        context: CampaignContext, *args) -> CallbackResult:
        """
        Execute a callback with unified error handling and result processing.
        
        Args:
            callback_func: The user-provided callback function
            callback_type: Type of callback ("pre_launch", "pre_send", etc.)
            context: Campaign context object
            *args: Additional arguments to pass to callback
            
        Returns:
            CallbackResult indicating success, no-success, or crash
        """
        if not callback_func:
            return CallbackResult.SUCCESS
            
        context.stats['callbacks_executed'] += 1
        result = callback_func(context, *args)
        
        # Handle different return types
        if isinstance(result, CallbackResult):
            return result
        elif result is True or result == "success":
            return CallbackResult.SUCCESS
        elif result is False or result == "no_success":
            return CallbackResult.NO_SUCCESS
        elif result == "fail_crash" or result == "crash":
            return CallbackResult.FAIL_CRASH
        else:
            # Default to success for unknown return values (conservative fallback)
            return CallbackResult.SUCCESS
                
    
    def handle_crash(self, crash_source: str, packet: Optional[Packet], 
                    context: CampaignContext, exception: Optional[Exception] = None) -> None:
        """
        Handle crash scenarios with built-in logging and user callback.
        
        Args:
            crash_source: Source of the crash ("pre_launch", "pre_send", etc.)
            packet: The packet involved in the crash (if any)
            context: Campaign context
            exception: Exception that caused the crash (if any)
        """
        context.stats['crash_count'] += 1
        crash_info = CrashInfo(packet, crash_source, exception, context)
        
        # 1. Built-in crash packet logging (if enabled)
        if self.campaign.crash_packet_logging:
            self._internal_crash_logger(crash_info, context)
        
        # 2. User crash callback (if provided)
        if self.campaign.crash_callback:
            self.campaign.crash_callback(crash_info, context)
        
        # 3. Store crash in most recent history entry if available
        if context.iteration is not context.fuzz_history[-1].iteration:
            logger.error("Mismatch between context iteration and latest fuzz history entry iteration during crash handling.")
            raise RuntimeError("Iteration mismatch during crash handling.")

        if context.fuzz_history:
            latest_entry = context.fuzz_history[-1]
            latest_entry.crashed = True
            latest_entry.crash_info = crash_info
        
        # 4. Stop campaign execution
        context.is_running = False
    
    def handle_no_success(self, callback_type: str, context: CampaignContext, *args) -> None:
        """
        Handle no-success scenarios with optional user callback.
        
        Args:
            callback_type: Type of callback that returned no-success
            context: Campaign context
            *args: Additional arguments from the original callback
        """
        context.stats['no_success_count'] += 1
        
        if self.campaign.no_success_callback:
            self.campaign.no_success_callback(callback_type, context, *args)
        else:
            # Default logging if no user callback
            logger.warning(f"Callback {callback_type} returned no-success")
    

    #TODO clean this up and integrate with the reporter
    def _internal_crash_logger(self, crash_info: CrashInfo, context: CampaignContext) -> None:
        """
        Built-in crash packet logging with same interface as user crash callback.
        This can be disabled and replaced by user's own logging in their crash callback.
        
        Args:
            crash_info: Crash information object
            context: Campaign context
        """

        # Ensure crash log directory exists
        crash_dir = Path(self.campaign.crash_log_directory)
        crash_dir.mkdir(parents=True, exist_ok=True)

        crash_id = crash_info.crash_id

        # Log crash metadata
        target_info = getattr(self.campaign.socket_config, 'target', 'N/A') if self.campaign.socket_config else 'N/A'
        metadata = {
            "crash_id": crash_id,
            "timestamp": crash_info.timestamp.isoformat(),
            "crash_source": crash_info.crash_source,
            "campaign_name": self.campaign.name or "unnamed",
            "target": str(target_info),
            "exception": str(crash_info.exception) if crash_info.exception else None,
            "stats": context.stats.copy()
        }

        if crash_info.packet:
            metadata["packet_summary"] = crash_info.packet.summary()
            pcap_path = crash_dir / f"{crash_id}.pcap"
            report_path = crash_dir / f"{crash_id}_report.txt"
            # Write crash report using new focused function
            write_crash_report(
                packet=crash_info.packet,
                file_path=str(report_path),
                metadata=metadata,
                campaign_context=context,
                crash_info=crash_info,
                pcap_path=str(pcap_path)
            )
        # JSON metadata (always created)
        with (crash_dir / f"{crash_id}_metadata.json").open("w") as f:
            json.dump(metadata, f, indent=2, default=str)
        logger.error(f"Crash logged: {crash_id} in {crash_dir}/")

class FuzzField:
    """
    A special field wrapper that embeds fuzzing configuration directly into packet definitions.
    
    This allows you to specify fuzzing parameters directly in the packet constructor:
    TCP(dport=FuzzField(values=[22, 80, 443], dictionaries=["ports.txt"]))

    - dictionary_override: If True, only use these dictionaries for this field (do not merge with user/default)
    - mutators: Can be a list of strings or dict of {mutator_name: weight}. 
      List format is converted to equal weights automatically.
      Examples:
        mutators=["libfuzzer", "scapy"]  # Equal weights (0.5 each)
        mutators={"libfuzzer": 0.7, "dictionary_only": 0.3}  # Weighted selection
    """
    
    def __init__(self, 
                 values: Optional[list[Any]] = None,
                 dictionaries: Optional[list[str]] = None,
                 fuzz_weight: float = 1.0,
                 description: str = "",
                 mutators: Optional[Union[list[str], dict[str, float]]] = None,
                 scapy_fuzz_weight: float = 0.1,
                 use_scapy_fuzz: bool = False,
                 dictionary_only_weight: float = 0.0,
                 dictionary_override: bool = False):
        """Initialize FuzzField with field-specific fuzzing configuration."""
        self.values = values or []
        self.dictionaries = dictionaries or []
        self.fuzz_weight = fuzz_weight
        self.description = description
        
        # Normalize mutators to dict format immediately
        if isinstance(mutators, list):
            # Convert list to equal-weight dict for backward compatibility
            if not mutators:
                self.mutators = {"libfuzzer": 1.0}
            else:
                equal_weight = 1.0 / len(mutators)
                self.mutators = {mutator: equal_weight for mutator in mutators}
        elif isinstance(mutators, dict):
            self.mutators = mutators.copy()
        
        self.scapy_fuzz_weight = scapy_fuzz_weight
        self.use_scapy_fuzz = use_scapy_fuzz
        self.dictionary_only_weight = dictionary_only_weight
        self.dictionary_override = dictionary_override

    def choose_value(self) -> Any:
        """Choose a random value from the values list or return None."""
        if self.values:
            return random.choice(self.values)
        return None
    
    def _coerce_to_bytes(self) -> bytes:
        """Convert the chosen value to bytes for Scapy compatibility."""
        val = self.choose_value()
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        if val is None:
            return b""
        return str(val).encode()
    
    def __len__(self) -> int:
        """Return the length of the coerced bytes representation."""
        return len(self._coerce_to_bytes())
    
    def __getitem__(self, idx: int) -> int:
        """Get item from the coerced bytes representation."""
        data = self._coerce_to_bytes()
        return data[idx]
    
    def __iter__(self) -> Iterator[int]:
        """Iterate over bytes representation."""
        return iter(self._coerce_to_bytes())
    
    def __int__(self) -> int:
        """Convert to integer representation."""
        val = self.choose_value()
        return int(val) if val is not None else 0
    
    def __str__(self) -> str:
        """String representation of FuzzField."""
        val = self.choose_value()
        return str(val) if val is not None else ""
    
    def __bytes__(self) -> bytes:
        """Bytes representation of FuzzField."""
        return self._coerce_to_bytes()
    
    def __repr__(self) -> str:
        """Detailed representation of FuzzField."""
        return f"FuzzField(values={self.values})"

    # Support concatenation with bytes/str to cooperate with Scapy encoders
    def __add__(self, other: Union[bytes, bytearray, str]) -> Union[bytes, object]:
        if isinstance(other, (bytes, bytearray)):
            return self._coerce_to_bytes() + bytes(other)
        if isinstance(other, str):
            return self._coerce_to_bytes() + other.encode()
        return NotImplemented

    def __radd__(self, other: Union[bytes, bytearray, str]) -> Union[bytes, object]:
        if isinstance(other, (bytes, bytearray)):
            return bytes(other) + self._coerce_to_bytes()
        if isinstance(other, str):
            return other.encode() + self._coerce_to_bytes()
        return NotImplemented

def configure_interface_offload(interface: str, features: List[str], disable: bool = True) -> tuple[bool, dict]:
    """
    Configure network interface offload features using ethtool.
    
    Args:
        interface: Network interface name (e.g., "eth0")
        features: List of offload features to configure
        disable: Whether to disable (True) or enable (False) features
        
    Returns:
        Tuple of (success_status, original_settings) where original_settings
        can be used for restoration later
        
    Raises:
        PermissionError: If not running as root
        FileNotFoundError: If ethtool command not available
        RuntimeError: If interface not found or configuration fails
    """
    # Check for root privileges
    if os.geteuid() != 0:
        raise PermissionError("Root privileges required for interface configuration")
    
    # Check if ethtool is available
    if not shutil.which("ethtool"):
        raise FileNotFoundError("ethtool command not found - install ethtool package")
    
    # Validate interface exists
    if not os.path.exists(f"/sys/class/net/{interface}"):
        raise RuntimeError(f"Network interface '{interface}' not found")
    
    original_settings: dict = {}
    action = "off" if disable else "on"
    action_desc = "Disabling" if disable else "Enabling"
    
    # Query current settings for restoration later
    for feature in features:
        try:
            result = subprocess.run(
                ["ethtool", "-k", interface],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.split('\n'):
                if feature in line and ':' in line:
                    current_state = line.split(':')[1].strip().split()[0]
                    original_settings[feature] = current_state
                    break
        except subprocess.CalledProcessError:
            logger.warning(f"Failed to query feature '{feature}' on '{interface}'")
    
    # Apply new settings
    success_count = 0
    for feature in features:
        if feature not in original_settings:
            continue  # Skip features we couldn't query since it either doesn't exist or we didnt back it up
        try:
            subprocess.run(
                ["ethtool", "-K", interface, feature, action],
                capture_output=True,
                text=True,
                check=True
            )
            success_count += 1
            logger.info(f"{action_desc} {feature} on {interface}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure {feature} on {interface}: {e}")
    
    if success_count == 0 and features:
        raise RuntimeError(f"Failed to configure any offload features on {interface}")
    
    logger.info(f"Successfully configured {success_count}/{len(features)} offload features on {interface}")
    return True, original_settings



def restore_interface_offload(interface: str, original_settings: dict) -> bool:
    """
    Restore network interface offload features to their original state.
    
    Args:
        interface: Network interface name
        original_settings: Dictionary of feature -> original_state mappings
        
    Returns:
        bool: True if restoration was successful
    """
    if not original_settings:
        return True  # Nothing to restore
    
    if os.geteuid() != 0:
        logger.warning("Cannot restore interface settings: root privileges required")
        return False
    
    if not shutil.which("ethtool"):
        logger.warning("Cannot restore interface settings: ethtool not available")
        return False
    
    success_count = 0
    for feature, original_state in original_settings.items():
        try:
            subprocess.run(
                ["ethtool", "-K", interface, feature, original_state],
                capture_output=True,
                text=True,
                check=True
            )
            success_count += 1
            logger.info(f"Restored {feature} to {original_state} on {interface}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore {feature} on {interface}: {e}")
    
    if success_count > 0:
        logger.info(f"Restored {success_count}/{len(original_settings)} interface settings on {interface}")
    
    return success_count == len(original_settings)

class FuzzingCampaign:
    """
    Base fuzzing campaign class with embedded packet configuration support.
    
    Campaign-level attributes control execution environment:
        - target: Target addresses (single or list)
        - name: Campaign name
        - layer: Network layer (default 3)
        - iterations: Number of iterations (default 1000)
        - duration: Time-based execution (seconds)
        - rate_limit: Packet rate limit (packets/second, default 10.0)
        - response_timeout: Timeout for response capture (seconds, default 2.0)
        - verbose: Enable verbose logging (default True)
        - output_network: Whether to send packets on the network (default True)
        - output_pcap: PCAP output filename (default None - disabled)
        - stats_interval: Statistics reporting interval (seconds, default 10.0)
        - timing: Timing control (optional)
        - capture_responses: Whether to capture responses (default False)
        - global_dict_config_path: Path to global dictionary configuration file
        - dictionary_config_file: Path to user dictionary configuration file (overrides defaults)
        - disable_interface_offload: Disable network interface hardware offload features (default False)
        - interface_offload_features: List of specific offload features to disable (None = use defaults)
        - interface_offload_restore: Restore original interface settings after campaign (default True)
        - excluded_layers: List of layer names to exclude from fuzzing (sets fuzz_weight=0.0)
        - layers_to_fuzz: List of layer names to fuzz exclusively (excludes all other layers)
        - excluded_fields: List of field patterns to exclude from fuzzing (supports *.field, Layer.*, Layer.field)
        - fields_to_fuzz: List of field patterns to fuzz exclusively (whitelist approach, excludes all others)
    
    Packet-level configuration is now embedded in the packet object itself using:
        packet[Layer].field_fuzz('fieldname').dictionary = ["dict1.txt", "dict2.txt"]
        packet[Layer].field_fuzz('fieldname').default_values = [value1, value2, value3]
        packet[Layer].field_fuzz('fieldname').weight = 0.8
        packet[Layer].fuzz_config().dictionary = ["packet_dict.txt"]
    """
    
    # Campaign defaults - consolidated in one place
    iterations = DEFAULT_ITERATIONS
    duration = None
    rate_limit = DEFAULT_RATE_LIMIT
    response_timeout = DEFAULT_RESPONSE_TIMEOUT
    # Logging configuration (can be True/False for backward compatibility, or integer for detailed levels)
    verbose: Union[bool, int] = True  # True = INFO level, False = WARNING+ only, int = custom verbose level for special features
    output_network = True
    output_pcap: Optional[str] = None  # PCAP output file path (None = disabled)
    append_pcap = False  # Whether to append to existing PCAP file or overwrite
    stats_interval = DEFAULT_STATS_INTERVAL
    capture_responses = False
    global_dict_config_path: Optional[str] = None  # Path to global dictionary config file
    packet: Optional[Packet] = None
    name: Optional[str] = None
    reuse_socket: bool = False  # Whether to reuse the same socket for all sends (default False)    
    
    
    # Callback configuration
    pre_launch_callback: Optional[Callable] = None
    pre_connect_callback: Optional[Callable] = None  # New: called before accept_connection/listen
    pre_send_callback: Optional[Callable] = None
    post_send_callback: Optional[Callable] = None
    crash_callback: Optional[Callable] = None
    no_success_callback: Optional[Callable] = None
    monitor_callback: Optional[Callable] = None
    custom_send_callback: Optional[Callable] = None
    
    # Crash logging configuration
    crash_packet_logging = True  # Enable/disable built-in crash packet capture
    crash_log_directory = DEFAULT_CRASH_LOG_DIR  # Directory for crash artifacts
    crash_log_format = "both"  # "scapy", "binary", or "both"

    # Advanced field/dictionary mapping overrides
    advanced_field_mapping_overrides: Optional[List[dict]] = None  # Inline campaign overrides
    user_mapping_file: Optional[str] = None  # Path to user-provided mapping file (JSON or Python)
    mapping_merge_mode: str = "merge"  # 'merge' or 'override'
    
    # Mutator configuration
    mutator_preference: Optional[Union[List[str], Dict[str, float]]] = None  # Campaign mutator preference (normalized to dict in __init__)
    
    # Layer-weight scaling controls (campaign-level overrides)
    # Lower values reduce fuzzing of outer layers more aggressively:
    #   - 0.9: Mild reduction (outer layers get 90% → 81% → 73% of base weight)
    #   - 0.5: Moderate reduction (outer layers get 50% → 25% → 12.5% of base weight)  
    #   - 0.1: Aggressive reduction (outer layers get 10% → 1% → 0.1% of base weight)
    enable_layer_weight_scaling: bool = True
    layer_weight_scaling: Optional[float] = None  # None uses default from default_mappings

    fuzz_weight_scaling: Optional[float] = None  # None uses default from default_mappings

    # Optionally exclude layers from fuzzing by name (sets fuzz_weight=0.0 for those layers)
    excluded_layers: Optional[List[str]] = None
    # Optionally specify only certain layers to fuzz (sets fuzz_weight=0.0 for all other layers)
    layers_to_fuzz: Optional[List[str]] = None
    
    # Field-level inclusion/exclusion with pattern matching support
    # Supports patterns like: "TCP.dport", "*.dport", "HTTP.*", "Raw.load"
    excluded_fields: Optional[List[str]] = None
    # Whitelist approach: only fuzz these specific fields (excludes all others)
    fields_to_fuzz: Optional[List[str]] = None

    # Network interface offload management for malformed packet fuzzing
    disable_interface_offload: bool = False                    # Enable/disable interface offload management
    interface_offload_features: Optional[List[str]] = None     # Specific features to disable (None = use defaults)
    interface_offload_restore: bool = True                     # Restore original settings after campaign

    # Reporting configuration
    report_formats: List[str] = ['markdown']                       # List of report formats to generate (html, json, csv, sarif, markdown, yaml)
    report_level: str = "advanced"                                  # Report detail level (executive, technical, forensics, advanced)

    # --- Socket logic additions ---
    socket_config: Optional[object] = None
    # Behavior when mutated packet fails to serialize to bytes
    # Options:
    #  - 'fail' : raise RuntimeError (strict, default)
    #  - 'skip' : do not write PCAP for this iteration and do not send
    pcap_serialize_failure_mode: str = 'fail'
    
    # Sequential field fuzzing configuration
    # When enabled, only one field is fuzzed per iteration (similar to boofuzz behavior)
    # Respects fields_to_fuzz/excluded_fields and layer filtering
    sequential_field_fuzzing: bool = False


    def __init__(self):
        """Initialize campaign with callback manager and handle excluded_layers."""
        
        # Deep copy all mutable class attributes to instance attributes
        for attr_name in dir(self.__class__):
            # Skip magic methods, private attrs, and methods
            if (not attr_name.startswith('__') and 
                not callable(getattr(self.__class__, attr_name))):
                
                # Get class attribute value
                class_value = getattr(self.__class__, attr_name)
                
                # Only deep copy mutable types (list, dict, set)
                if isinstance(class_value, (list, dict, set)):
                    instance_value = copy.deepcopy(class_value)
                    setattr(self, attr_name, instance_value)
        
        # Normalize mutator_preference to dict format if it's a list
        if isinstance(self.mutator_preference, list):
            equal_weight = 1.0 / len(self.mutator_preference)
            self.mutator_preference = {mutator: equal_weight for mutator in self.mutator_preference}
        
        # Validate field inclusion/exclusion: both cannot be set in same campaign
        if (self.fields_to_fuzz and self.excluded_fields):
            raise ValueError(
                "Campaign cannot have both 'fields_to_fuzz' (whitelist) and 'excluded_fields' (blacklist) set. "
                "Use either whitelist approach (fields_to_fuzz) or blacklist approach (excluded_fields), but not both."
            )
        
        if self.layers_to_fuzz and self.excluded_layers:
            raise ValueError(
                "Campaign cannot have both 'layers_to_fuzz' (whitelist) and 'excluded_layers' (blacklist) set. "
                "Use either whitelist approach (layers_t_fuzz) or blacklist approach (excluded_layers), but not both."
            )
        
        # Handle 'all' in report_formats
        if 'all' in self.report_formats:
            self.report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']
        
        # Initialize instance-specific objects
        self.callback_manager = CallbackManager(self)
        self.context = CampaignContext(self)  # Initialize context immediately
        self.monitor_thread = None
        self._original_offload_settings = {}
        self._interface_configured = False
        
        # Handle excluded_layers by adding advanced mapping entries
        if self.excluded_layers:
            if not self.advanced_field_mapping_overrides:
                self.advanced_field_mapping_overrides = []
            self.advanced_field_mapping_overrides.extend([
                {"layer": lname, "fuzz_weight": 0.0} for lname in self.excluded_layers
            ])

        # Handle layers_to_fuzz by setting weight to 0.0 for all layers except those specified
        # Only apply whitelist logic if layers_to_fuzz is explicitly provided (not None)
        if self.layers_to_fuzz is not None:
            whitelisted_layers = set(self.layers_to_fuzz)
            
            # Special case: empty layers_to_fuzz means exclude everything
            if not whitelisted_layers:
                if not self.advanced_field_mapping_overrides:
                    self.advanced_field_mapping_overrides = []
                # Add universal layer exclusion
                self.advanced_field_mapping_overrides.append({
                    'fuzz_weight': 0.0,
                    'description': 'Universal layer exclusion: empty layers_to_fuzz list'
                })
            else:
                # Get layers from packet or fallback to all known layers
                layer_names = get_layer_names_from_packets(self.packet) if self.packet else []
                all_layer_names = set(layer_names) if layer_names else {
                    field_key.split('.')[0] for field_key in FIELD_NAME_WEIGHTS.keys() if '.' in field_key
                }
                
                # Exclude layers not in layers_to_fuzz
                layers_to_exclude = all_layer_names - whitelisted_layers
                if layers_to_exclude:
                    if not self.advanced_field_mapping_overrides:
                        self.advanced_field_mapping_overrides = []
                    self.advanced_field_mapping_overrides.extend([
                        {"layer": lname, "fuzz_weight": 0.0} for lname in layers_to_exclude
                    ])

        # Handle excluded_fields with pattern matching support
        if self.excluded_fields:
            if not self.advanced_field_mapping_overrides:
                self.advanced_field_mapping_overrides = []
            self.advanced_field_mapping_overrides.extend(
                parse_field_patterns(self.excluded_fields, exclude=True)
            )

        # Handle fields_to_fuzz (whitelist approach) - exclude all fields except those specified
        # Only apply whitelist logic if fields_to_fuzz is explicitly provided (not None)
        if self.fields_to_fuzz is not None:
            whitelisted_patterns = set(self.fields_to_fuzz)
            
            # Special case: empty fields_to_fuzz means exclude everything
            if not whitelisted_patterns:
                if not self.advanced_field_mapping_overrides:
                    self.advanced_field_mapping_overrides = []
                # Add universal field exclusion
                self.advanced_field_mapping_overrides.append({
                    'fuzz_weight': 0.0,
                    'description': 'Universal field exclusion: empty fields_to_fuzz list'
                })
            # Only process the whitelist logic if we have actual patterns to whitelist
            elif whitelisted_patterns:
                # Extract layer names from whitelisted patterns (e.g., "TCP.dport" -> "TCP")
                whitelisted_layers = {
                    pattern.split('.', 1)[0] for pattern in whitelisted_patterns 
                    if '.' in pattern and not pattern.endswith('.*') and pattern.split('.', 1)[0] != '*'
                }
                
                # First, exclude all known patterns that don't match whitelist
                all_known_patterns = set(FIELD_NAME_WEIGHTS.keys())
                known_fields_to_exclude = [
                    pattern for pattern in all_known_patterns 
                    if not pattern_matches_any(pattern, whitelisted_patterns)
                    and not (pattern.endswith('.*') and pattern[:-2] in whitelisted_layers)
                ]
                
                # Second, create a catch-all exclusion for any unknown fields
                # This ensures fields not in FIELD_NAME_WEIGHTS are also excluded unless whitelisted
                if not self.advanced_field_mapping_overrides:
                    self.advanced_field_mapping_overrides = []
                    
                # Add known field exclusions
                if known_fields_to_exclude:
                    self.advanced_field_mapping_overrides.extend(
                        parse_field_patterns(known_fields_to_exclude, exclude=True)
                    )
                
                # Add catch-all exclusion with whitelist exceptions
                # This excludes all fields by default, then allows only whitelisted ones
                for pattern in whitelisted_patterns:
                    # Add explicit inclusion for whitelisted patterns 
                    if '.' in pattern:
                        layer, field = pattern.split('.', 1)
                        self.advanced_field_mapping_overrides.append({
                            'layer': layer,
                            'field': field,
                            'fuzz_weight': 1.0,
                            'description': f'Whitelist inclusion: {pattern}'
                        })
                    else:
                        # Pattern like "Path" or "Host" - matches any layer
                        self.advanced_field_mapping_overrides.append({
                            'field': pattern,
                            'fuzz_weight': 1.0,
                            'description': f'Whitelist inclusion: {pattern} (any layer)'
                        })
                
                # Add universal exclusion for everything else (lowest priority)
                self.advanced_field_mapping_overrides.append({
                    'fuzz_weight': 0.0,
                    'description': 'Default exclusion: fields_to_fuzz whitelist mode'
                })


    def validate_campaign(self) -> bool:
        """
        Validate campaign configuration before execution.
        
        This method performs runtime validation that cannot be done during initialization:
        - Resolves dynamic packets via get_packet() method
        - Validates network configuration requirements
        - Ensures socket/packet layer compatibility
        
        Returns:
            bool: True if campaign is valid and ready for execution
        """
        #TODO remove this maybe?
        errors = []
        packet = getattr(self, 'packet', None)
        
        # If no packet assigned, try to obtain one via get_packet()
        if packet is None:
            get_fn = getattr(self, 'get_packet', None)
            if callable(get_fn):
                packet = get_fn()
                if packet is not None:
                    # Ensure get_packet() returned a Scapy Packet instance
                    if not isinstance(packet, Packet):
                        errors.append("get_packet() did not return a scapy Packet instance")
                    else:
                        self.packet = packet
                        logger.debug(f"Campaign packet resolved via get_packet(): {get_layer_name(packet)}")
        
        if packet is None:
            errors.append("Campaign packet is None - set 'packet' attribute or implement 'get_packet()' method")
        
        # Only require socket_config if network output is enabled
        if self.output_network and self.socket_config is None:
            errors.append("Campaign socket_config is None - must provide socket configuration when output_network=True")
        
        socket_type = self.context.fuzz_socket.socket_type if self.context.fuzz_socket else None
        
        # Validate socket configuration and packet compatibility
        if self.socket_config and socket_type is not None:
            if not isinstance(socket_type, SocketType):
                errors.append(f"Socket returned invalid socket_type {socket_type}, must be a SocketType enum value")
            else:
                # Check socket/packet layer compatibility
                if isinstance(packet, Packet):
                    if socket_type == SocketType.RAW_ETHERNET:
                        from scapy.layers.l2 import Ether
                        if not packet.haslayer(Ether):
                            errors.append("RAW_ETHERNET socket requires packet with Ethernet header")
                    elif socket_type in [SocketType.RAW_IP, SocketType.RAW_TCP, SocketType.RAW_UDP]:
                        from scapy.layers.inet import IP
                        if not packet.haslayer(IP):
                            errors.append(f"{socket_type.name} socket requires packet with IP header")
        
        # Log validation errors
        if errors:
            logger.error("Campaign validation failed:")
            for error in errors:
                logger.error(f"  • {error}")
        else:
            logger.debug("Campaign validation passed")
        
        return not errors



    def get_pcap_path(self) -> Optional[Path]:
        """
        Get PCAP output path with automatic directory creation.
        Returns None if PCAP output is disabled.
        Falls back to current directory if specified path is invalid.
        """
        if not self.output_pcap:
            # Generate smart default based on campaign name
            if self.name:
                # Convert campaign name to valid filename
                safe_name = "".join(c.lower() if c.isalnum() else "_" for c in self.name)
                safe_name = safe_name.strip("_")
                filename = f"{safe_name}.pcap"
            else:
                filename = DEFAULT_PCAP_FILENAME
            pcap_path = Path(filename)
        else:
            pcap_path = Path(self.output_pcap)
        
        # If it's just a filename (no directory), use default pcaps directory
        if pcap_path.parent == Path('.'):
            pcap_dir = Path(DEFAULT_PCAP_DIR)
            pcap_dir.mkdir(parents=True, exist_ok=True)
            pcap_path = pcap_dir / pcap_path.name
        else:
            # Try to create the specified directory
            try:
                pcap_path.parent.mkdir(parents=True, exist_ok=True)
            except (PermissionError, OSError) as e:
                # Fallback to current directory with same filename
                fallback_path = Path.cwd() / pcap_path.name
                logger.warning(f"Cannot create directory {pcap_path.parent}: {e}")
                logger.warning(f"Falling back to: {fallback_path}")
                pcap_path = fallback_path
            
        return pcap_path
    
    def _create_iteration_history_entry(self, iteration: int, packet, mutator_data) -> 'FuzzHistoryEntry':
        """Create a history entry for this iteration with runtime execution metadata and essential packet data."""
        history_entry = FuzzHistoryEntry(
            timestamp_sent=datetime.now(),
            iteration=iteration,
        )
        
        # Add essential packet data without causing memory issues
        if packet:
            # Store packet bytes for reproduction
            history_entry.packet_bytes = bytes(packet)
            history_entry.payload_size = len(history_entry.packet_bytes)
            history_entry.payload_hash = hashlib.md5(history_entry.packet_bytes).hexdigest()

        # Manage history size limit
        if len(self.context.fuzz_history) >= self.context.max_history_size:
            self.context.fuzz_history.pop(0)  # Remove oldest entry
        
        # Add entry to history
        self.context.fuzz_history.append(history_entry)
        
        return history_entry


    def _serialize_packet(self, packet, iteration: int) -> tuple[bytes | None, bool]:
        """
        Serialize packet to bytes and apply campaign target addressing.
        
        This function:
        1. Applies campaign target addressing to the original packet for network sending
        2. Serializes the packet to bytes for network transmission
        
        Args:
            packet: Original fuzzed packet
            iteration: Current iteration number for error tracking
            
        Returns:
            tuple: (packet_bytes, serialize_success)
                - packet_bytes: Serialized bytes for network transmission (None if failed)
                - serialize_success: True if serialization succeeded, False otherwise
        """
        # Apply campaign target addressing to the original packet for network sending
        # This will be used for cases where the packet layer being fuzzed is also the layer used for addressing
        socket_type = self.context.fuzz_socket.socket_type if self.context.fuzz_socket else None
        
        # This is a best effort approach and may not cover all cases
        # Setting the target directly in the packet definition may be better
        if (socket_type in (SocketType.RAW_IP, SocketType.RAW_UDP, SocketType.RAW_TCP)) and packet.haslayer(IP):
            target = getattr(self.socket_config, 'target', None) if self.socket_config else None
            if target:
                packet[IP].dst = target
        elif socket_type == SocketType.RAW_ETHERNET and packet.haslayer(Ether):
            target = getattr(self.socket_config, 'target', None) if self.socket_config else None
            if target:
                packet[Ether].dst = target
        
        # Serialize the packet to bytes
        pkt_bytes = None
        serialize_success = True
        try:
            pkt_bytes = bytes(packet)
            
                
        except Exception as e:
            serialize_success = False
            logger.error(f"[SERIALIZE] Failed to serialize mutated packet: {e}")
            
            # Mark serialization failure in history entry
            if self.context.fuzz_history:
                self.context.fuzz_history[-1].serialization_failed = True
                self.context.fuzz_history[-1].serialization_error = str(e)
                
                # Collect structured failure info for consolidated summary
                if not hasattr(self.context, 'serialize_failures'):
                    self.context.serialize_failures = []  # type: ignore[attr-defined]
                self.context.serialize_failures.append({  # type: ignore[attr-defined]
                    'iteration': iteration,
                    'packet': packet,  # Use original fuzzed packet for error analysis
                    'error': str(e)
                })

            mode = getattr(self, 'pcap_serialize_failure_mode', 'fail')
            if mode == 'fail':
                # Strict mode: raise immediately
                raise RuntimeError(f"Failed to serialize mutated packet: {e}") from e
            else:
                # 'skip' mode: do not write or send for this iteration
                logger.info("[SERIALIZE] Skipping send for this iteration due to serialize failure")
                pkt_bytes = None

        # Store serialized bytes in history entry
        self.context.fuzz_history[-1].packet_bytes = pkt_bytes
        self.context.fuzz_history[-1].payload_size = len(pkt_bytes)
        
        return pkt_bytes, serialize_success

    def execute(self) -> bool:
        """
        Execute the fuzzing campaign lifecycle, including validation, callback execution, fuzzer setup, and main fuzzing loop.
        
        This method performs the following steps:
            1. Validates the campaign configuration and packet setup.
            2. Executes the pre-launch callback, if provided.
            3. Checks for required permissions (e.g., root for network operations).
            4. Initializes the fuzzer and mutator data for the campaign.
            5. Starts the monitor thread if a monitor callback is configured.
            6. Logs campaign information and configuration details.
            7. Runs the main fuzzing loop, which handles per-iteration packet mutation, socket management, callbacks, PCAP logging, and response capture.
            8. Stops the monitor thread after completion.
            9. Handles exceptions, errors, and campaign crashes with appropriate callbacks and logging.
           10. Generates campaign summary reports and optionally dumps packet history for verbose runs.
        
        Returns:
            bool: True if the campaign completed successfully, False otherwise.
        """
        try:
            # Create socket first so we can validate against its type
            # Even when network is disabled, we need socket for proper PCAP formatting and validation
            from .sockets.socket_interface import create as create_fuzz_socket
            self.context.fuzz_socket = create_fuzz_socket(self)
            if self.context.fuzz_socket is None:
                raise RuntimeError("Failed to create fuzzing socket with provided configuration")

            # Validate campaign configuration now that socket is available
            if not self.validate_campaign():
                raise ValueError("Campaign validation failed")


            # Check permissions for network operations
            if self.output_network and os.geteuid() != 0:
                raise PermissionError("Root privileges required for network operations")

            # Create fuzzer
            # Determine fuzz mode from campaign attributes
            #TODO does having both still make sense?
            fuzz_mode = FuzzMode.BOTH  # Default
            if hasattr(self, 'fuzz_mode'):
                mode_str = getattr(self, 'fuzz_mode', 'both').lower()
                if mode_str == 'field':
                    fuzz_mode = FuzzMode.FIELD_LEVEL
                elif mode_str == 'binary' or mode_str == 'packet':
                    fuzz_mode = FuzzMode.PACKET_LEVEL
                elif mode_str == 'both':
                    fuzz_mode = FuzzMode.BOTH
                elif mode_str == 'none':
                    fuzz_mode = FuzzMode.BOTH  # Keep BOTH but will skip mutations
            
            config = FuzzConfig(
                mode = fuzz_mode,
                use_dictionaries = True,
                fuzz_weight = self.fuzz_weight_scaling if self.fuzz_weight_scaling is not None else DEFAULT_FUZZ_WEIGHT_SCALING,
                global_dict_config_path = self.global_dict_config_path,
                mutator_preference = self.mutator_preference if self.mutator_preference is not None else DEFAULT_MUTATOR_PREFERENCE,
                enable_layer_weight_scaling = self.enable_layer_weight_scaling,
                layer_weight_scaling = self.layer_weight_scaling,
                # Include packet and iteration information in config
                packets = self.packet,
                iterations = self.iterations,
                # Pass campaign-level field mapping overrides
                advanced_field_mapping_overrides = getattr(self, 'advanced_field_mapping_overrides', None),
                # Pass sequential field fuzzing flag
                sequential_field_fuzzing = getattr(self, 'sequential_field_fuzzing', False)
            )
            fuzzer = MutatorManager(config)
            self.context.mutator_data = fuzzer.fuzz_packet()

            # Display campaign information
            logger.info(f"Starting campaign: {self.name or 'Unnamed Campaign'}")
            target_info = getattr(self.socket_config, 'target', 'N/A') if self.socket_config else 'N/A'
            logger.info(f"   Target: {target_info}")
            logger.info(f"   Iterations: {self.iterations}")
            logger.info(f"   Layer: {self.context.fuzz_socket.socket_type}")
            logger.info(f"   Rate limit: {self.rate_limit} packets/sec")
            pkt_for_info = getattr(self, 'packet', None)
            if hasattr(pkt_for_info, 'has_fuzz_config') and pkt_for_info.has_fuzz_config():  # type: ignore[attr-defined]
                logger.info("   ### Packet has embedded fuzzing configuration")
            if self.pre_launch_callback or self.pre_send_callback or self.post_send_callback or self.crash_callback or self.no_success_callback or self.monitor_callback:
                logger.info("   ### Callbacks enabled")

            # Start monitor thread if callback provided
            self._start_monitor_thread()

            # Execute pre-launch callback
            result = self.callback_manager.execute_callback(
                self.pre_launch_callback, "pre_launch", self.context
            )
            if result == CallbackResult.FAIL_CRASH:
                self.callback_manager.handle_crash("pre_launch", None, self.context)
                return False
            elif result == CallbackResult.NO_SUCCESS:
                self.callback_manager.handle_no_success("pre_launch", self.context)

            # Execute fuzzing iterations
            success = self._run_fuzzing_loop()

            # Stop monitor thread
            self._stop_monitor_thread()

            return success

        except Exception as e:
            logger.error(f"--- Campaign execution failed: {e}")

            # Stop monitor thread on error
            self._stop_monitor_thread()

            # Handle as crash if context exists
            self.callback_manager.handle_crash("execute", None, self.context, e)

            raise
        finally:
            # Always write a concise campaign summary at the end
            try:
                # Use the main reporting engine for campaign summaries
                generate_campaign_reports(
                    campaign=self,
                    campaign_context=self.context,
                    level=getattr(self, 'report_level', 'executive'),
                    output_formats=self.report_formats,
                    output_directory=None  # Auto-generated path
                )
                
                # For very verbose runs (verbosity >= 3), dump the entire packet history
                if hasattr(self, 'verbose') and isinstance(self.verbose, int) and self.verbose >= 3:
                    if self.context.fuzz_history:
                        from datetime import datetime
                        
                        # Create logs directory if it doesn't exist
                        log_dir = Path("artifacts/logs")
                        log_dir.mkdir(parents=True, exist_ok=True)
                        
                        # Generate filename with timestamp
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        campaign_name = getattr(self, 'name', 'unknown_campaign')
                        dump_filename = f"fuzz_history_{campaign_name}_{timestamp}.log"
                        dump_path = log_dir / dump_filename
                        
                        # Write the packet history dump
                        write_fuzz_history_dump(
                            fuzz_history=self.context.fuzz_history,
                            file_path=str(dump_path),
                            verbose_level=self.verbose,
                            title=f"Packet History Dump - {campaign_name}",
                            mutator_data=getattr(self.context, 'mutator_data', None)
                        )
                        
                        logger.info(f"Packet history dump written to: {dump_path}")
                    
            except Exception as _e:
                # Do not fail execution due to logging errors
                logger.warning(f"Failed to write campaign summary: {_e}")

    def _start_monitor_thread(self) -> None:
        """Start monitor callback thread if provided"""
        if self.monitor_callback:
            self.monitor_thread = threading.Thread(
                target=self._monitor_wrapper,
                args=(self.context,),
                daemon=True
            )
            self.monitor_thread.start()
            logger.debug("Monitor thread started")
    
    def _stop_monitor_thread(self) -> None:
        """Stop monitor thread gracefully"""
        self.context.is_running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)  # 5 second timeout
            logger.debug("Monitor thread stopped")
    
    def _monitor_wrapper(self, context: CampaignContext) -> None:
        """Wrapper for monitor callback execution"""
        try:
            result = self.callback_manager.execute_callback(
                self.monitor_callback, "monitor", context
            )
            
            if result == CallbackResult.FAIL_CRASH:
                self.callback_manager.handle_crash("monitor", None, context)
            elif result == CallbackResult.NO_SUCCESS:
                self.callback_manager.handle_no_success("monitor", context)
                
        except Exception as e:
            logger.error(f"Monitor thread failed: {e}")
            self.callback_manager.handle_crash("monitor", None, context, e)


    def _run_fuzzing_loop(self) -> bool:
        """
        Run the main fuzzing loop with callback integration.
        
        This implementation includes PCAP output, target resolution, 
        rate limiting, callback execution, and proper network/file output handling.
        """
        # Initialize counters and state
        packets_sent = 0
        packets_written_to_pcap = 0
        serialize_failure_count = 0
        start_time = time.time()
        pcap_writer = None
        mutator_data = self.context.mutator_data
        fuzzed_packets = mutator_data.fuzzed_packets
        try:
            # Configure network interface
            #TODO move some of this to the socket code
            network_enabled = bool(self.output_network)
            if self.disable_interface_offload and network_enabled:
                features_to_disable = self.interface_offload_features or DEFAULT_OFFLOAD_FEATURES
                interface_name = getattr(self.socket_config, 'interface', None) if self.socket_config else None
                if not interface_name:
                    raise RuntimeError("Interface name required for offload configuration - socket_config.interface cannot be None")
                logger.info(f"Configuring interface {interface_name} for malformed packet fuzzing")
                logger.info(f"Disabling features: {', '.join(features_to_disable)}")
                success, original_settings = configure_interface_offload(
                    interface_name,
                    features_to_disable,
                    disable=True
                )
                if success:
                    self._original_offload_settings = original_settings
                    self._interface_configured = True
                    logger.info(f"Interface {interface_name} configured successfully")
                else:
                    raise RuntimeError(f"Failed to configure interface {interface_name}")
            
            # Setup PCAP writer
            pcap_path = self.get_pcap_path()
            if pcap_path:
                logger.debug(f"Using PCAP file: {pcap_path}")
                logger.info(f"Initializing PCAP output to: {pcap_path}")
                from scapy.utils import PcapWriter
                # Always use Ethernet linktype since _complete_packet_layers() adds Ethernet headers
                # to all packets written to PCAP, regardless of original packet layers
                linktype = 1  # Ethernet linktype for proper PCAP encapsulation
                pcap_writer = PcapWriter(str(pcap_path), append=self.append_pcap, sync=True, linktype=linktype)


            # Only open socket and initialize networking if network is enabled and reusing socket
            if network_enabled and self.reuse_socket:
                self.context.fuzz_socket.open()
                # Handle server mode initialization
                if hasattr(self.context.fuzz_socket, 'start_listening'):
                    self.context.fuzz_socket.start_listening()
                    self.context.fuzz_socket.accept_connection()
                self.context.socket = getattr(self.context.fuzz_socket, 'raw', None)

##Iterate over the fuzzed packets
            for iteration in range(self.iterations):
                # Update context with current iteration
                self.context.iteration = iteration
                packet = fuzzed_packets[iteration]

                # Check if campaign should continue (monitor thread may have stopped it)
                if not self.context.is_running:
                    logger.info("Campaign stopped by monitor callback")
                    break
                
                # Check duration limit
                if self.duration and (time.time() - start_time) >= self.duration:
                    break

## Clear sockets and anything let voer from previous iteration
                if network_enabled and not self.reuse_socket:
                    try:
                        self.context.fuzz_socket.close()
                        self.context.fuzz_socket = None
                        self.context.socket = None
                    except Exception as e:
                        logger.warning(f"Failed to close socket from previous iteration: {e}")


## Preconnect callback
                if self.pre_connect_callback:
                    result = self.callback_manager.execute_callback(
                        self.pre_connect_callback, "pre_connect", self.context, packet
                    )
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("pre_connect", packet, self.context)
                        return False
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("pre_connect", self.context, packet)
                        return False

##Open socket for non-reuse case
                if network_enabled and not self.reuse_socket:
                    # Socket already created above, just need to open it for network operations
                    self.context.fuzz_socket.open()

                    # Handle server mode initialization
                    if hasattr(self.context.fuzz_socket, 'start_listening'):
                        self.context.fuzz_socket.start_listening()
                        self.context.fuzz_socket.accept_connection()
                    self.context.socket = getattr(self.context.fuzz_socket, 'raw', None)

##Presend callback            
                # Execute pre-send callback with error handling
                if self.pre_send_callback:
                    result = self.callback_manager.execute_callback(
                        self.pre_send_callback, "pre_send", self.context, packet
                    )
                    
                    #TODO make sure we handle the failures correctly
                    # Handle callback result - determine if execution should continue
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("pre_send", packet, self.context)
                        return False
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("pre_send", self.context, packet)
                        return False

##Serialize and log packet                   
                # Log fuzzed fields for this iteration
                fuzzed_fields = mutator_data.get_fuzzed_fields_for_packet(iteration)
                fuzzed_fields_str = ', '.join(fuzzed_fields) if fuzzed_fields else 'None'
                logger.debug(f"[SEND] Iteration {iteration}: {packet.summary()}")
                logger.debug(f"[SEND] Fuzzed fields: {fuzzed_fields_str}")

                # Common pre-processing for all packet send types
                history_entry = self._create_iteration_history_entry(iteration, packet, mutator_data)
                pkt_bytes, serialize_success = self._serialize_packet(packet, iteration)
                
                # Update serialize failure count
                if not serialize_success:
                    serialize_failure_count += 1
                    self.context.stats['serialize_failure_count'] = serialize_failure_count
                    continue  # Skip sending if serialization failed, move to next iteration
                if not pkt_bytes:
                    logger.debug("[SEND] No packet bytes to send, skipping iteration")
                    continue # Move to next iteration
                
                # Write to PCAP if enabled and serialization succeeded
                if pcap_writer:
                    # Use socket's PCAP preparation method for consistent formatting
                    pcap_bytes = self.context.fuzz_socket.prepare_for_pcap_logging(pkt_bytes, packet, iteration)
                    pcap_writer.write(pcap_bytes)
                    packets_written_to_pcap += 1
                    logger.debug(f"[PCAP] Wrote packet to PCAP file")

##Send fuzzed packets
                #TODO evaluate response passing flow
                response = None
                send_success = False
                # Execute custom send callback (replaces default packet sending behavior)
                if self.custom_send_callback:
                    result = self.callback_manager.execute_callback(
                        self.custom_send_callback, "custom_send", self.context, packet
                    )
                    
                    # Custom send callback error handling
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("custom_send", packet, self.context)
                        continue  # Move to next iteration
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("custom_send", self.context, packet)
                        continue  # Move to next iteration
                else:
                    if network_enabled and self.output_network and self.context.fuzz_socket:
                        send_result = self.context.fuzz_socket.send_packet(pkt_bytes, self.context)
                        send_success = bool(send_result) if send_result is not None else False
                        if send_success:
                            logger.debug(f"[SEND] Sent {len(pkt_bytes)} bytes")
                        else:
                            logger.error(f"[SEND] Failed to send packet")
                            continue  # Move to next iteration
                    else:
                        send_success = False
                        
##Receive response
                # Capture response if not already captured and conditions are met
                if network_enabled and self.capture_responses and self.context.fuzz_socket:
                    if hasattr(self.context.fuzz_socket, 'receive_response'):
                        response = self.context.fuzz_socket.receive_response(timeout=self.response_timeout)
                        self.context.fuzz_history[-1].timestamp_received = datetime.now()
                        self.context.fuzz_history[-1].response = response

##Post send callback           
                # Execute post-send callback
                #TODO, cleanup callbacks interface
                if self.post_send_callback:
                    result = self.callback_manager.execute_callback(
                        self.post_send_callback, "post_send", self.context, fuzzed_packets[iteration], response
                    )
                    
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("post_send", fuzzed_packets[iteration], self.context)
                        continue  # Move to next iteration
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("post_send", self.context, fuzzed_packets[iteration], response)
                        continue  # Move to next iteration
                
                
                packets_sent += 1
                self.context.stats['packets_sent'] = packets_sent
                self.context.stats['serialize_failure_count'] = serialize_failure_count

##Close socket if not reusing
                if network_enabled and self.context.fuzz_socket and not self.reuse_socket:
                    self.context.fuzz_socket.close()
                    self.context.fuzz_socket = None
                    self.context.socket = None
                
##Rate limiting
                # Only apply rate limiting if network sending is enabled
                if self.rate_limit and network_enabled:
                    time.sleep(1.0 / self.rate_limit)
            
##End of itterations loop

            # Close fuzz_socket if we opened it for reuse
            if network_enabled and self.context.fuzz_socket and self.reuse_socket:
                self.context.fuzz_socket.close()
                self.context.fuzz_socket = None
                self.context.socket = None

            logger.info(f"Campaign completed: {packets_sent} packets processed")
            if pcap_path:
                logger.info(f"PCAP output: {packets_written_to_pcap} packets written to {pcap_path}")
            logger.info(f"Stats: {self.context.stats}")
            
            return True
            
        except KeyboardInterrupt:
            logger.info(f"[INTERRUPT] Campaign interrupted: {packets_sent} packets processed")
        finally:
            # Always restore interface settings regardless of how we exit
            if self._interface_configured and self.interface_offload_restore and self._original_offload_settings:
                try:
                    interface_name = getattr(self.socket_config, 'interface', None) if self.socket_config else None
                    if not interface_name:
                        raise RuntimeError("Interface name required for offload restoration - socket_config.interface cannot be None")
                    logger.info(f"Restoring interface {interface_name} to original settings")
                    success = restore_interface_offload(interface_name, self._original_offload_settings)
                    if success:
                        logger.info(f"Interface {interface_name} restored successfully")
                    else:
                        logger.warning(f"Failed to fully restore interface {interface_name} settings")
                except Exception as e:
                    logger.error(f"Error restoring interface {interface_name}: {e}")
                finally:
                    self._interface_configured = False
                    self._original_offload_settings = {}
            # Close fuzz_socket if it exists
            if self.context.fuzz_socket:
                try:
                    self.context.fuzz_socket.close()
                    logger.debug("Closed campaign fuzz_socket.")
                except Exception as e:
                    logger.warning(f"Failed to close campaign fuzz_socket: {e}")
            # The raw socket (self.context.socket) is managed by fuzz_socket, so no separate close needed.
            # Close PCAP writer if open
            if 'pcap_writer' in locals() and pcap_writer:
                pcap_writer.close()