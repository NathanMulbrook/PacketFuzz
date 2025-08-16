#!/usr/bin/env python3
"""
PacketFuzz Framework

This module provides a class-based framework for defining fuzzing campaigns,
similar to how Scapy defines packets and fields using class inheritance.

Integrates libFuzzer mutation engine with Scapy packet definitions and 
FuzzDB dictionaries for comprehensive network protocol fuzzing.

Now uses embedded packet configuration with field_fuzz() and fuzz_config() methods.
"""

from __future__ import annotations
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.can import CAN 
from scapy.packet import Raw, Packet, fuzz
from scapy.sendrecv import send, sendp, sniff, sr1
from typing import Dict, List, Union, Any, Optional, Callable, Protocol
from enum import Enum
import os
import sys
import random
import time
import logging
import copy
import json
import threading
import subprocess
import shutil
from datetime import datetime
from scapy.utils import wrpcap
from mutator_manager import MutatorManager, FuzzConfig, FuzzMode
from utils.packet_report import write_packet_report, write_campaign_summary
from pathlib import Path
from dataclasses import dataclass, field

# Constants
DEFAULT_INTERFACE = "eth0"
DEFAULT_PCAP_FILENAME = "fuzzing_session.pcap"
DEFAULT_ITERATIONS = 1000
DEFAULT_RATE_LIMIT = 500.0
DEFAULT_RESPONSE_TIMEOUT = 2.0
DEFAULT_STATS_INTERVAL = 10.0

# Default directories
DEFAULT_PCAP_DIR = "pcaps"
DEFAULT_LOG_DIR = "logs"
DEFAULT_CRASH_LOG_DIR = "crash_logs"

# Default interface offload features to disable for malformed packet fuzzing
DEFAULT_OFFLOAD_FEATURES = [
    "tx-checksumming",      # Transmit checksum offloading
    "rx-checksumming",      # Receive checksum offloading  
    "tcp-segmentation-offload",  # TCP segmentation offload (TSO)
    "generic-segmentation-offload",  # Generic segmentation offload (GSO)
    "generic-receive-offload",   # Generic receive offload (GRO)
    "large-receive-offload"      # Large receive offload (LRO)
]

# Configure logging with default log directory. Logging is required; exit if file logging cannot be initialized.
log_dir = Path(DEFAULT_LOG_DIR)
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except Exception:
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
    except Exception as e:
        print("[ERROR] Failed to initialize file logging at logs/packetfuzz.log.")
        print("        Please ensure you have write permissions and no root-owned logs remain.")
        print(f"        Details: {e}")
        raise SystemExit(2)
logger = logging.getLogger(__name__)

# Install packet extensions for embedded configuration
try:
    from packet_extensions import install_packet_extensions
    install_packet_extensions()
except ImportError:
    pass


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

    def __post_init__(self):
        self.crash_id = f"crash_{self.timestamp.strftime('%Y%m%d_%H%M%S_%f')}"


@dataclass
class FuzzHistoryEntry:
    """Tracks a single fuzzing iteration with sent packet, response, and crash info"""
    packet: Optional[Packet] = None
    timestamp_sent: Optional[datetime] = None
    timestamp_received: Optional[datetime] = None
    response: Optional[Any] = None
    crashed: bool = False
    crash_info: Optional[CrashInfo] = None
    iteration: int = -1
    
    def get_response_time(self) -> Optional[float]:
        """Calculate response time in milliseconds if both timestamps are available"""
        if self.timestamp_sent and self.timestamp_received:
            delta = self.timestamp_received - self.timestamp_sent
            return delta.total_seconds() * 1000
        return None

#TODO evaluate if this is needed
@dataclass
class CampaignContext:
    """Shared context passed to all callbacks"""
    campaign: Any
    is_running: bool = True
    stats: dict = field(default_factory=lambda: {
        'packets_sent': 0,
        'callbacks_executed': 0,
        'no_success_count': 0,
        'crash_count': 0
    })
    shared_data: dict = field(default_factory=dict)  # User data sharing between callbacks
    start_time: float = field(default_factory=time.time)
    fuzz_history: List[FuzzHistoryEntry] = field(default_factory=list)
    fuzz_history_errors: List[Packet] = field(default_factory=list)
    max_history_size: int = 1000  # Limit history size to prevent memory issues
    socket: Optional[Any] = None  # Placeholder for socket object if needed


class CallbackManager:
    """
    Unified callback execution and management.
    Handles all user and internal callbacks with error handling.
    Logs crashes and invokes user crash callbacks.
    """
    
    def __init__(self, campaign: Any):
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
            
        try:
            context.stats['callbacks_executed'] += 1
            result = callback_func(*args, context)
            
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
                # Default to success for unknown return values this may be a bad assumption
                 return CallbackResult.SUCCESS
                
        except Exception as e:
            logger.error(f"Callback {callback_type} failed with exception: {e}")
            # Treat exceptions as crashes
            return CallbackResult.FAIL_CRASH
    
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
            try:
                self.campaign.crash_callback(crash_info, context)
            except Exception as e:
                logger.error(f"User crash callback failed: {e}")
        
        # 3. Store crash in most recent history entry if available
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
            try:
                self.campaign.no_success_callback(callback_type, context, *args)
            except Exception as e:
                logger.error(f"No-success callback failed: {e}")
        else:
            # Default logging if no user callback
            logger.warning(f"Callback {callback_type} returned no-success")
    
    def _internal_crash_logger(self, crash_info: CrashInfo, context: CampaignContext) -> None:
        """
        Built-in crash packet logging with same interface as user crash callback.
        This can be disabled and replaced by user's own logging in their crash callback.
        
        Args:
            crash_info: Crash information object
            context: Campaign context
        """
        try:
            # Ensure crash log directory exists
            crash_dir = Path(self.campaign.crash_log_directory)
            crash_dir.mkdir(parents=True, exist_ok=True)

            crash_id = crash_info.crash_id

            # Log crash metadata
            metadata = {
                "crash_id": crash_id,
                "timestamp": crash_info.timestamp.isoformat(),
                "crash_source": crash_info.crash_source,
                "campaign_name": self.campaign.name or "unnamed",
                "target": str(self.campaign.target),
                "exception": str(crash_info.exception) if crash_info.exception else None,
                "stats": context.stats.copy()
            }

            if crash_info.packet:
                metadata["packet_summary"] = crash_info.packet.summary()
                pcap_path = crash_dir / f"{crash_id}.pcap"
                report_path = crash_dir / f"{crash_id}_report.txt"
                # Write combined report (handles PCAP internally)
                write_packet_report(
                    packet=crash_info.packet,
                    file_path=str(report_path),
                    mode="w",
                    metadata=metadata,
                    campaign_context=context,
                    crash_info=crash_info,
                    pcap_path=str(pcap_path)
                )
            # JSON metadata (always created)
            with (crash_dir / f"{crash_id}_metadata.json").open("w") as f:
                json.dump(metadata, f, indent=2, default=str)
            logger.error(f"Crash logged: {crash_id} in {crash_dir}/")

        except Exception as e:
            logger.error(f"Failed to log crash packet: {e}")


class FuzzMutator(Enum):
    """Available fuzzing mutators with libFuzzer integration"""
    DICTIONARY = "dictionary"          # Use FuzzDB dictionary entries with mutations
    DICTIONARY_ONLY = "dictionary_only" # Use only raw dictionary values without mutations
    LIBFUZZER = "libfuzzer"            # Use libFuzzer mutation engine
    PYTHON_MUTATOR = "python_mutator"  # Use Python-based mutation engine


class FuzzField:
    """
    A special field wrapper that embeds fuzzing configuration directly into packet definitions.
    
    This allows you to specify fuzzing parameters directly in the packet constructor:
    TCP(dport=FuzzField(values=[22, 80, 443], dictionaries=["ports.txt"]))

    - dictionary_override: If True, only use these dictionaries for this field (do not merge with user/default)
    - mutators: Must be a list of strings or None. If a list, a random mutator will be chosen.
    """
    
    def __init__(self, 
                 values: Optional[list[Any]] = None,
                 dictionaries: Optional[list[str]] = None,
                 fuzz_weight: float = 1.0,
                 description: str = "",
                 mutators: Optional[list[str]] = None,
                 scapy_fuzz_weight: float = 0.1,
                 use_scapy_fuzz: bool = False,
                 dictionary_only_weight: float = 0.0,
                 dictionary_override: bool = False):
        self.values = values or []
        self.dictionaries = dictionaries or []
        self.fuzz_weight = fuzz_weight
        self.description = description
        if mutators is not None and not isinstance(mutators, list):
            raise TypeError("FuzzField 'mutators' must be a list of strings or None.")
        self.mutators = mutators if mutators is not None else ["libfuzzer"]
        self.scapy_fuzz_weight = scapy_fuzz_weight
        self.use_scapy_fuzz = use_scapy_fuzz
        self.dictionary_only_weight = dictionary_only_weight
        self.dictionary_override = dictionary_override

    def choose_value(self) -> Any:
        """
        Choose a value for fuzzing: random from values list if present, else default_value.
        """
        if self.values:
            return random.choice(self.values)
        return None
    
    # Provide sequence-like behavior so Scapy can safely interact with this object
    def _coerce_to_bytes(self) -> bytes:
        val = self.choose_value()
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        if val is None:
            return b""
        return str(val).encode()
    
    def __len__(self) -> int:
        try:
            return len(self._coerce_to_bytes())
        except Exception:
            return 0
    
    def __getitem__(self, idx):
        data = self._coerce_to_bytes()
        return data[idx]
    
    def __iter__(self):
        return iter(self._coerce_to_bytes())
    
    def __int__(self) -> int:
        val = self.choose_value()
        return int(val) if val is not None else 0
    
    def __str__(self) -> str:
        val = self.choose_value()
        return str(val) if val is not None else ""
    
    def __bytes__(self) -> bytes:
        return self._coerce_to_bytes()
    
    def __repr__(self) -> str:
        return f"FuzzField(values={self.values})"

    # Support concatenation with bytes/str to cooperate with Scapy encoders
    def __add__(self, other):
        if isinstance(other, (bytes, bytearray)):
            return self._coerce_to_bytes() + bytes(other)
        if isinstance(other, str):
            return self._coerce_to_bytes() + other.encode()
        return NotImplemented

    def __radd__(self, other):
        if isinstance(other, (bytes, bytearray)):
            return bytes(other) + self._coerce_to_bytes()
        if isinstance(other, str):
            return other.encode() + self._coerce_to_bytes()
        return NotImplemented

def configure_interface_offload(interface: str, features: List[str], disable: bool = True) -> tuple[bool, dict]:
    """
    Configure network interface offload features using ethtool.
    Returns (success, original_settings) for potential restoration later.
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
    
    try:
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
                continue  # Skip features we couldn't query
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
        
        if success_count == 0:
            raise RuntimeError(f"Failed to configure any offload features on {interface}")
        
        logger.info(f"Successfully configured {success_count}/{len(features)} offload features on {interface}")
        return True, original_settings
    except Exception as e:
        logger.error(f"Interface configuration failed: {e}")
        return False, original_settings


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


# Fuzz config inheritance mode: 'nearest' (default, inherited) or 'explicit' (only direct config)
FUZZ_CONFIG_INHERITANCE_MODE = "nearest"

class FuzzingCampaign:
    """
    Base fuzzing campaign class with embedded packet configuration support.
    
    Campaign-level attributes control execution environment:
        - target: Target addresses (single or list)
        - name: Campaign name
        - layer: Network layer (default 3)
        - interface: Network interface for L2 fuzzing (default 'eth0')
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
    interface = DEFAULT_INTERFACE   #TODO this is a string, should it get converted to a scapy interface object
    verbose = True   #TODO implement conf.verb
    output_network = True
    output_pcap: Optional[str] = None  # PCAP output file path (None = disabled)
    stats_interval = DEFAULT_STATS_INTERVAL
    capture_responses = False
    global_dict_config_path: Optional[str] = None  # Path to global dictionary config file
    packet: Optional[Packet] = None
    target: Optional[Any] = None
    name: Optional[str] = None
    
    # Callback configuration
    pre_launch_callback: Optional[Callable] = None
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
    mutator_preference: Optional[List[str]] = None  # Campaign mutator preference (defaults to ["libfuzzer"])

    # Optionally exclude layers from fuzzing by name (sets fuzz_weight=0.0 for those layers)
    excluded_layers: Optional[List[str]] = None
    fuzz_start_layer: Optional[str] = None  # Layer name to attach PacketFuzzConfig to (default: base layer)

    # Network interface offload management for malformed packet fuzzing
    disable_interface_offload: bool = False                    # Enable/disable interface offload management
    interface_offload_features: Optional[List[str]] = None     # Specific features to disable (None = use defaults)
    interface_offload_restore: bool = True                     # Restore original settings after campaign

    # --- Socket logic additions ---
    socket_type: Optional[str] = None    # User can specify: 'l2', 'l3', 'tcp', 'udp', "canbus" or None for auto
    # Behavior when mutated packet fails to serialize to bytes
    # Options:
    #  - 'fail' : raise RuntimeError (strict, default)
    #  - 'skip' : do not write PCAP for this iteration and do not send
    pcap_serialize_failure_mode: str = 'fail'



    def __init__(self):
        """Initialize campaign with callback manager and handle excluded_layers."""
        import copy
        
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
        
        # Set default for mutator_preference if None
        if getattr(self, 'mutator_preference', None) is None:
            self.mutator_preference = ["libfuzzer"]
        
        # Initialize instance-specific objects
        self.callback_manager = CallbackManager(self)
        self.context = None
        self.monitor_thread = None
        self._original_offload_settings = {}
        self._interface_configured = False
        
        # Handle excluded_layers by adding advanced mapping entries
        if isinstance(getattr(self, 'excluded_layers', None), list) and self.excluded_layers:
            exclude_entries = [
                {"layer": lname, "fuzz_weight": 0.0} for lname in self.excluded_layers
            ]
            if not hasattr(self, 'advanced_field_mapping_overrides') or self.advanced_field_mapping_overrides is None:
                self.advanced_field_mapping_overrides = []
            self.advanced_field_mapping_overrides.extend(exclude_entries)

    def create_fuzzer(self, mutator_preference: Optional[list[str]] = None) -> 'MutatorManager':
        """
        Create a packetfuzz instance configured for this campaign.
        mutator_preference: Override the campaign's default mutator preference.
                           If None, uses self.mutator_preference.
        """
        # Use parameter if provided, otherwise use campaign's default
        effective_preference = mutator_preference or self.mutator_preference or ["libfuzzer"]
        
        dict_config_path = self.user_mapping_file or self.global_dict_config_path
        config = FuzzConfig(
            mode = FuzzMode.BOTH,
            use_dictionaries = True,
            fuzz_weight = 1.0,
            global_dict_config_path = dict_config_path,
            mutator_preference = effective_preference
        )
        return MutatorManager(config)

    def get_packet_with_embedded_config(self) -> Optional[Packet]:
        """
        Get the campaign packet with embedded configuration applied.
        This method can be overridden by subclasses to programmatically
        add embedded configuration to packets.
        In the new FuzzField-direct approach, we pass FuzzField objects 
        directly to the mutator without extraction.
        
        Provides backward compatibility with get_packet() method.
        """
        # First try the packet attribute
        if self.packet is not None:
            return self.packet
        
        # Backward compatibility: try get_packet() method
        if hasattr(self, 'get_packet') and callable(getattr(self, 'get_packet')):
            return getattr(self, 'get_packet')()  # type: ignore
        
        return None

    def validate_campaign(self) -> bool:
        """Validate campaign configuration"""
        errors = []
        
        # Check if we have a packet from either attribute or method
        packet = self.get_packet_with_embedded_config()
        if packet is None:
            errors.append("Campaign packet is None (set packet attribute or implement get_packet method)")
        if self.target is None:
            errors.append("Campaign target is None")
        # Validate socket_type if specified
        if self.socket_type is not None:
            valid_types = ['l2', 'l3', 'tcp', 'udp', 'canbus']
            if self.socket_type not in valid_types:
                errors.append(f"Invalid socket_type {self.socket_type}, must be one of {valid_types}")
            if packet and self.socket_type == "l2" and not packet.haslayer(Ether):
                errors.append("Layer 2 (socket_type='l2') campaign requires Ethernet header")
            if packet and self.socket_type in ["l3", "tcp", "udp"] and not packet.haslayer(IP):
                errors.append(f"socket_type='{self.socket_type}' campaign requires IP header")
        
        # Log validation errors if verbose mode is enabled
        if errors and self.verbose:
            for error in errors:
                logger.error(error)
        
        return len(errors) == 0

    def get_pcap_path(self) -> Optional[Path]:
        """
        Get PCAP output path with automatic directory creation.
        Returns None if PCAP output is disabled.
        Falls back to current directory if specified path is invalid.
        """
        if not self.output_pcap:
            return None
            
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

    def execute(self) -> bool:
        """
        Execute the fuzzing campaign with full callback support.
        """
        try:
            # Initialize campaign context
            self.context = CampaignContext(self)
            
            # Validate campaign configuration
            if not self.validate_campaign():
                raise ValueError("Campaign validation failed")

            # Execute pre-launch callback
            result = self.callback_manager.execute_callback(
                self.pre_launch_callback, "pre_launch", self.context
            )

            if result == CallbackResult.FAIL_CRASH:
                self.callback_manager.handle_crash("pre_launch", None, self.context)
                return False
            elif result == CallbackResult.NO_SUCCESS:
                self.callback_manager.handle_no_success("pre_launch", self.context)

            # Check permissions for network operations
            if self.output_network and os.geteuid() != 0:
                raise PermissionError("Root privileges required for network operations")

            # Create fuzzer
            fuzzer = self.create_fuzzer()

            # Get packet with embedded config
            packet = self.get_packet_with_embedded_config()
            if packet is None:
                if self.verbose:
                    logger.error("No packet available for fuzzing")
                return False

            # Start monitor thread if callback provided
            self._start_monitor_thread()

            # Display campaign information
            if self.verbose:
                logger.info("Starting campaign: %s", self.name or 'Unnamed Campaign')
                logger.info("   Target: %s", self.target)
                logger.info("   Iterations: %s", self.iterations)
                logger.info("   Layer: %s", self.socket_type)
                logger.info("   Rate limit: %s packets/sec", self.rate_limit)
                if hasattr(packet, 'has_fuzz_config') and packet.has_fuzz_config():  # type: ignore[attr-defined]
                    logger.info("   ### Packet has embedded fuzzing configuration")
                if self.pre_launch_callback or self.pre_send_callback or self.post_send_callback or self.crash_callback or self.no_success_callback or self.monitor_callback:
                    logger.info("   ### Callbacks enabled")

            # Execute fuzzing iterations
            success = self._run_fuzzing_loop(fuzzer, packet)

            # Stop monitor thread
            self._stop_monitor_thread()

            return success

        except Exception as e:
            if self.verbose:
                logger.error(f"--- Campaign execution failed: {e}")

            # Stop monitor thread on error
            self._stop_monitor_thread()

            # Handle as crash if context exists
            if self.context:
                self.callback_manager.handle_crash("execute", None, self.context, e)

            return False
        finally:
            # Always write a concise campaign summary at the end
            try:
                write_campaign_summary(self, self.context)
            except Exception as _e:
                # Do not fail execution due to logging errors
                if self.verbose:
                    logger.warning(f"Failed to write campaign summary: {_e}")

    def _start_monitor_thread(self) -> None:
        """Start monitor callback thread if provided"""
        if self.monitor_callback and self.context:
            self.monitor_thread = threading.Thread(
                target=self._monitor_wrapper,
                args=(self.context,),
                daemon=True
            )
            self.monitor_thread.start()
            if self.verbose:
                logger.info("Monitor thread started")
    
    def _stop_monitor_thread(self) -> None:
        """Stop monitor thread gracefully"""
        if self.context:
            self.context.is_running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)  # 5 second timeout
            if self.verbose:
                logger.info("Monitor thread stopped")
    
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



    def _run_fuzzing_loop(self, fuzzer: 'MutatorManager', packet: Packet) -> bool:
        """
        Run the main fuzzing loop with callback integration.
        
        This implementation includes PCAP output, target resolution, 
        rate limiting, callback execution, and proper network/file output handling.
        """
        packets_sent = 0
        packets_written_to_pcap = 0
        serialize_failure_count = 0
        start_time = time.time()
        pcap_writer = None
        merged_field_mapping = self._load_merged_field_mapping()
        # ...existing code (rest of method body, properly indented)...
        
        try:
            # Configure network interface offload settings if enabled
            network_enabled = bool(self.output_network)
            if self.disable_interface_offload and network_enabled:
                features_to_disable = self.interface_offload_features or DEFAULT_OFFLOAD_FEATURES
                
                if self.verbose:
                    logger.info(f"Configuring interface {self.interface} for malformed packet fuzzing")
                    logger.info(f"Disabling features: {', '.join(features_to_disable)}")
                
                success, original_settings = configure_interface_offload(
                    self.interface, 
                    features_to_disable, 
                    disable=True
                )
                
                if success:
                    self._original_offload_settings = original_settings
                    self._interface_configured = True
                    if self.verbose:
                        logger.info(f"Interface {self.interface} configured successfully")
                else:
                    raise RuntimeError(f"Failed to configure interface {self.interface}")
            
            # Initialize PCAP writer if PCAP output is enabled
            pcap_path = self.get_pcap_path()
            if pcap_path:
                if self.verbose:
                    logger.debug(f"Using PCAP file: {pcap_path}")
                    logger.info(f"Initializing PCAP output to: {pcap_path}")
                try:
                    from scapy.utils import PcapWriter
                    # Choose linktype so raw bytes (IP) are stored correctly in PCAP
                    linktype = 1  # Default to Ethernet
                    try:
                        if packet is not None:
                            if packet.haslayer(Ether):
                                linktype = 1
                            elif packet.haslayer(IP):
                                # RAW IP packets should use LINKTYPE_RAW (101)
                                linktype = 101
                    except Exception:
                        # If detection fails, keep default
                        linktype = 1

                    pcap_writer = PcapWriter(str(pcap_path), append=False, sync=True, linktype=linktype)
                except Exception as e:
                    logger.error(f"[PCAP] Failed to initialize writer for {pcap_path}: {e}")
                    # Fallback: try current working directory with same filename
                    try:
                        fallback_path = Path.cwd() / Path(str(pcap_path)).name
                        if self.verbose:
                            logger.warning(f"[PCAP] Falling back to cwd: {fallback_path}")
                        pcap_writer = PcapWriter(str(fallback_path), append=False, sync=True)
                        pcap_path = fallback_path
                    except Exception as e2:
                        logger.error(f"[PCAP] Fallback writer initialization failed: {e2}")
            # Create empty list in case no packet is provided
            fuzzed_packets = [None] * self.iterations
            # Create the fuzzed packets
            if packet and not self.custom_send_callback:
                fuzzed_packets = fuzzer.fuzz_fields(packet, self.iterations, merged_field_mapping=merged_field_mapping)            
            #Iterate over the fuzzed packets
            for itteration in range(self.iterations or 1000):
                # Check if campaign should continue (monitor thread may have stopped it)
                if self.context and not self.context.is_running:
                    if self.verbose:
                        logger.info("Campaign stopped by monitor callback")
                    break
                
                # Check duration limit
                if self.duration and (time.time() - start_time) >= self.duration:
                    break
                
                # Auto-detect socket type from packet if not specified
                if not self.socket_type:
                    if packet and packet.haslayer(TCP):
                        self.socket_type = 'tcp'
                    elif packet and packet.haslayer(UDP):
                        self.socket_type = 'udp'
                    elif packet and packet.haslayer(IP):
                        self.socket_type = 'l3'
                    elif packet and packet.haslayer(Ether):
                        self.socket_type = 'l2'
                    elif packet and packet.haslayer(CAN):
                        self.socket_type = 'canbus'
                    else:
                        raise ValueError("Cannot auto-detect socket type from packet and non speciied- please specify socket_type")

                # Open sockets for sending only if network output is enabled
                # TODO: make this also accept functions that return a socket object
                if network_enabled:
                    import socket
                    if self.socket_type == 'l2':
                        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                        s.bind((self.interface, 0))
                    elif self.socket_type == 'canbus':
                        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
                        s.bind((self.interface,))
                    elif self.socket_type == 'tcp':
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    elif self.socket_type == 'udp':
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                    elif self.socket_type == 'l3':
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    else:
                        raise ValueError(f"Unknown socket_type: {self.socket_type}")
                    self.context.socket = s  # Store socket in context for custom send callback
                else:
                    self.context.socket = None

                # Execute pre-send callback with error handling
                if self.pre_send_callback and self.context:
                    result = self.callback_manager.execute_callback(
                        self.pre_send_callback, "pre_send", self.context, fuzzed_packets[itteration]
                    )
                    
                    # Handle callback result - determine if execution should continue
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("pre_send", fuzzed_packets[itteration], self.context)
                        return False
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("pre_send", self.context, fuzzed_packets[itteration])
                
                # Execute custom send callback (replaces default packet sending behavior)
                if self.custom_send_callback and self.context:
                    result = self.callback_manager.execute_callback(
                        self.custom_send_callback, "custom_send", self.context, fuzzed_packets[itteration]
                    )
                    
                    # Custom send callback error handling
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("custom_send", fuzzed_packets[itteration], self.context)
                        return False
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("custom_send", self.context, fuzzed_packets[itteration]) 
                # Default packet sending behavior (if no custom send callback)
                elif fuzzed_packets[itteration] is not None:
                    # Create history entry for this iteration
                    history_entry = FuzzHistoryEntry(
                        packet=fuzzed_packets[itteration],
                        timestamp_sent=datetime.now(),
                        iteration=itteration
                    )
                    
                    # Manage history size limit
                    if self.context and len(self.context.fuzz_history) >= self.context.max_history_size:
                        self.context.fuzz_history.pop(0)  # Remove oldest entry
                    
                    # Add entry to history
                    if self.context:
                        self.context.fuzz_history.append(history_entry)
                    
                    response = None  # Placeholder for response capture
                    
                    
                    # # Canbus using scapy send
                    # if self.socket_type == "canbus": 
                    #     try:
                    #         if fuzzed_packets[itteration] is None:
                    #             continue
                    #         # Serialize packet to bytes
                    #         pkt_bytes = bytes(fuzzed_packets[itteration])
                    #         send_success = self.context.socket.sendp()
                    #         if self.context and self.context.fuzz_history:
                    #             self.context.fuzz_history[-1].timestamp_received = datetime.now()
                    #             self.context.fuzz_history[-1].packet = pkt_bytes
                    #     except Exception as e:
                    #         if self.verbose:
                    #             logger.error(f"[SEND] Failed to send CAN packet: {e}")
                    #         send_success = None


                    # Send using Python socket
                
                    try:
                        pkt = fuzzed_packets[itteration]
                        if pkt is None:
                            continue
                        if self.verbose:
                            logger.info(f"[SEND] Sending: {pkt.summary()}")
                        # Apply campaign target addressing based on network layer (using local pkt)
                        try:
                            if (self.socket_type in ("l3", "udp", "tcp")) and pkt.haslayer(IP):
                                pkt[IP].dst = self.target
                            elif self.socket_type == "l2" and pkt.haslayer(Ether):
                                pkt[Ether].dst = self.target
                        except Exception:
                            pass
                        # Serialize packet to bytes first so PCAP contains exactly what is sent
                        pkt_bytes = None
                        serialize_error = None
                        try:
                            #TODO make sure there are no fuzz fields left, they should have been replaced with values.
                            pkt_bytes = bytes(pkt)
                        except Exception as e:
                            serialize_error = e
                            logger.error(f"[SERIALIZE] Failed to serialize mutated packet: {e}")
                            serialize_failure_count += 1
                            # Append the failed packet to error history for reporting
                            try:
                                if self.context is not None:
                                    self.context.fuzz_history_errors.append(pkt)
                            except Exception:
                                pass

                            if self.context:
                                self.context.stats['serialize_failure_count'] = serialize_failure_count

                            mode = getattr(self, 'pcap_serialize_failure_mode', 'fail')
                            if mode == 'fail':
                                # Strict mode: raise immediately
                                raise RuntimeError(f"Failed to serialize mutated packet: {e}") from e
                            else:
                                # 'skip' or unknown mode: do not write or send for this iteration
                                if self.verbose:
                                    logger.info("[PCAP] Skipping PCAP write/send for this iteration due to serialize failure")
                                pkt_bytes = None

                        # Write exact serialized bytes to PCAP for parity with network send
                        if pcap_writer and pkt_bytes is not None:
                            pcap_writer.write(pkt_bytes)
                            packets_written_to_pcap += 1
                            if self.verbose:
                                logger.debug(f"[PCAP] Wrote packet {packets_written_to_pcap}")
                        # Only send when network is enabled; PCAP-only mode skips sending
                        send_success = None

                        if network_enabled and self.output_network and self.context and self.context.socket and pkt_bytes is not None:
                            sock = self.context.socket
                            if self.socket_type == "l2":
                                # Layer 2: send raw Ethernet frame
                                send_success = sock.send(pkt_bytes)
                            else:
                                # Layer 3: send raw IP packet
                                # For AF_INET/SOCK_RAW, need to provide destination address
                                send_success = sock.sendto(pkt_bytes, (self.target, 0))

                        if self.context and self.context.fuzz_history:
                            self.context.fuzz_history[-1].timestamp_received = datetime.now()
                            # Store the packet object in history for analysis
                            self.context.fuzz_history[-1].packet = pkt
                    except Exception as e:
                        if self.verbose:
                            logger.error(f"[SEND] Failed to send packet: {e}")
                        send_success = None
                


                    # Receive a response if capture_responses is enabled
                    #TODO update for canbus
                    if network_enabled and self.capture_responses and send_success:
                        try:
                            if self.socket_type == "l2":
                                # Layer 2: Use sniff() with a filter for Ethernet frames
                                response = sniff(
                                    iface=self.interface,
                                    timeout=self.response_timeout,
                                    count=1,
                                    lfilter=lambda x: x.haslayer(Ether) and x[Ether].src == self.target
                                )
                            else:
                                # Layer 3: Use sr1() for IP packets with timeout
                                #TODO this should not send but it does
                                response = sr1(
                                    packet,
                                    iface=self.interface,
                                    timeout=self.response_timeout,
                                    verbose=self.verbose
                                )
                            
                            if self.verbose and response:
                                logger.info(f"[RECV] Response: {response.summary()}")
                            
                            # Update history entry with response information
                            if self.context and self.context.fuzz_history:
                                self.context.fuzz_history[-1].response = response
                                self.context.fuzz_history[-1].timestamp_received = datetime.now()
                        except Exception as e:
                            if self.verbose:
                                logger.error(f"[RECV] Failed to capture response: {e}")
                            response = None
                    
                # Execute post-send callback
                if self.post_send_callback and self.context:
                    result = self.callback_manager.execute_callback(
                        self.post_send_callback, "post_send", self.context, fuzzed_packets[itteration], response
                    )
                    
                    if result == CallbackResult.FAIL_CRASH:
                        self.callback_manager.handle_crash("post_send", fuzzed_packets[itteration], self.context)
                        return False
                    elif result == CallbackResult.NO_SUCCESS:
                        self.callback_manager.handle_no_success("post_send", self.context, fuzzed_packets[itteration], response)
                
                
                packets_sent += 1
                if self.context:
                    self.context.stats['packets_sent'] = packets_sent
                    self.context.stats['serialize_failure_count'] = serialize_failure_count
                
                # Rate limiting
                if self.rate_limit:
                    time.sleep(1.0 / self.rate_limit)
            
            
            if self.verbose:
                logger.info(f"Campaign completed: {packets_sent} packets processed")
                if pcap_path:
                    logger.info(f"PCAP output: {packets_written_to_pcap} packets written to {pcap_path}")
                if self.context:
                    logger.info(f"Stats: {self.context.stats}")
            
            return True
            
        except KeyboardInterrupt:
            if self.verbose:
                logger.info(f"[INTERRUPT] Campaign interrupted: {packets_sent} packets processed")
            return True
        except Exception as e:
            if self.verbose:
                logger.error(f"Fuzzing loop failed: {e}")
            return False
        finally:
            # Always restore interface settings regardless of how we exit
            if self._interface_configured and self.interface_offload_restore and self._original_offload_settings:
                try:
                    if self.verbose:
                        logger.info(f"Restoring interface {self.interface} to original settings")

                    success = restore_interface_offload(self.interface, self._original_offload_settings)
                    if success:
                        if self.verbose:
                            logger.info(f"Interface {self.interface} restored successfully")
                    else:
                        logger.warning(f"Failed to fully restore interface {self.interface} settings")
                except Exception as e:
                    logger.error(f"Error restoring interface {self.interface}: {e}")
                finally:
                    self._interface_configured = False
                    self._original_offload_settings = {}
            # Close socket if it exists in context
            if self.context and self.context.socket:
                try:
                    self.context.socket.close()
                    if self.verbose:
                        logger.info("Closed campaign socket.")
                except Exception as e:
                    logger.warning(f"Failed to close campaign socket: {e}")
            # Close PCAP writer if open
            if 'pcap_writer' in locals() and pcap_writer:
                try:
                    pcap_writer.close()
                except Exception:
                    pass

    def _load_merged_field_mapping(self) -> list:
        """
        Load and merge the advanced field/dictionary mapping for this campaign.
        Order of precedence:
        1. Default mapping (from default_mappings.py)
        2. User mapping file (if provided)
        3. Inline campaign overrides (if provided)
        Merge or override according to mapping_merge_mode.
        """
        from default_mappings import FIELD_ADVANCED_WEIGHTS
        import importlib.util
        import json
        import os

        def load_mapping_file(path):
            """Load mapping configuration from JSON or Python file."""
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Mapping file not found: {path}")
            if path.endswith('.json'):
                with open(path, 'r') as f:
                    return json.load(f)
            elif path.endswith('.py'):
                # Dynamically load Python module and extract configuration
                spec = importlib.util.spec_from_file_location("user_mapping", path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load Python mapping file: {path}")
                user_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(user_mod)
                return getattr(user_mod, 'FIELD_ADVANCED_WEIGHTS', [])
            else:
                raise ValueError(f"Unsupported mapping file type: {path}")

        # Start with framework defaults as base configuration
        merged = list(FIELD_ADVANCED_WEIGHTS)

        # Layer 2: Apply user mapping file if provided
        if self.user_mapping_file:
            user_map = load_mapping_file(self.user_mapping_file)
            if self.mapping_merge_mode == 'override':
                # Replace entire default configuration
                merged = list(user_map)
            else:  # merge
                # Combine with defaults, avoiding duplicates
                merged = merged + [m for m in user_map if m not in merged]

        # Layer 3: Apply inline campaign overrides (highest priority)
        if self.advanced_field_mapping_overrides:
            if self.mapping_merge_mode == 'override':
                # Replace all previous configuration
                merged = list(self.advanced_field_mapping_overrides)
            else:  # merge
                # Add to existing configuration, avoiding duplicates
                merged = merged + [m for m in self.advanced_field_mapping_overrides if m not in merged]

        return merged

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}(name={self.name}, "
                f"target={self.target}, "
                f"iterations={self.iterations}, "
                f"layer={self.socket_type})")
        
    def __post_init__(self):
        # After merging/overrides, attach PacketFuzzConfig to the correct layer
        if self.packet is not None:
            target_layer = self.packet
            if self.fuzz_start_layer:
                # Walk down layers to find the first matching layer name
                l = self.packet
                while l is not None:
                    if hasattr(l, 'name') and l.name == self.fuzz_start_layer:
                        target_layer = l
                        break
                    l = getattr(l, 'payload', None)
            # Build PacketFuzzConfig from merged campaign config (reuse existing merging logic)
            from packet_extensions import PacketFuzzConfig
            merged_cfg = PacketFuzzConfig()
            # Copy relevant campaign options to merged_cfg (add more as needed)
            merged_cfg.fuzz_weight = getattr(self, 'fuzz_weight', 1.0)
            merged_cfg.dictionary = getattr(self, 'dictionary', [])
            merged_cfg.mutators = getattr(self, 'mutator_preference', ["libfuzzer"])
            merged_cfg.use_scapy_fuzz = getattr(self, 'use_scapy_fuzz', False)
            merged_cfg.scapy_fuzz_weight = getattr(self, 'scapy_fuzz_weight', 0.1)
            merged_cfg.dictionary_only_weight = getattr(self, 'dictionary_only_weight', 0.0)
            # Attach resolved field mapping (not raw overrides)
            merged_cfg.field_matching = getattr(self, 'resolved_field_mapping', None)
            merged_cfg.description = getattr(self, 'description', "")
            # ...add more fields as needed...
            target_layer.fuzz_config().__dict__.update(merged_cfg.__dict__)